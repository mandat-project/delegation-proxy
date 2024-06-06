import express from 'express';
import { exportJWK, SignJWT, generateKeyPair, jwtVerify, decodeJwt, decodeProtectedHeader, importJWK, createRemoteJWKSet, calculateJwkThumbprint } from 'jose';
import { randomUUID } from 'crypto';
import log from 'npmlog';
import ruid from 'express-ruid';

// Set log level
log.level = 'verbose'

// Add timestamp to logging
Object.defineProperty(log, 'heading', { get: () => { return new Date().toISOString() } })
log.headingStyle = { bg: '', fg: 'blue' }

const app = express();

// Adding Express middleware for unique request id
app.use(ruid({
  setInContext: true,
  upBytes: 3,
  idMax: 9999,
  prefixRoot: '',
  prefixSeparator: ''
}));

async function forwardRequest(req, res) {
  // Make actual request
  let serverRes = await fetch(req.url, {
    method: req.method,
    body: req.body,
    headers: req.headers
  });

  // Copy header and status
  res.set(Object.fromEntries(serverRes.headers));
  res.status(serverRes.status);

  // Copy body
  let reader = serverRes.body.getReader();
  let done = false
  let value = '';
  while(!done) {
    res.write(value);
    ({ value, done } = await reader.read());
  }
  res.end();
}

// This function returns an Express.js middleware
async function delegationProxy(webId, idp, client_id, client_secret) {
  log.verbose('SDS-D', 'Starting SDS-D middleware');
  // Logging in with Solid OIDC

  log.verbose('SDS-D', `Logging in as ${webId}`);
  // Create keypair for signing DPoPs
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwkPublicKey = await exportJWK(publicKey);
  jwkPublicKey.alg = 'RS256';

  // Find token endpoint of IdP
  const oidc_config = await (await fetch(idp + '/.well-known/openid-configuration')).json();
  const token_endpoint = oidc_config['token_endpoint'];
  log.verbose('SDS-D', `Found token endpoint ${token_endpoint}`);

  // Save the current auth token here
  var currentAuthToken = null;
  // For every outgoing request this function should be called to see if
  // the auth token is still valid and otherwise get a new one
  async function getCurrentAuthToken() {
    if(currentAuthToken && decodeJwt(currentAuthToken).exp > (Date.now() / 1000 + 60 * 9)) {
      // Still valid (plus one minute in the future), nothing to do
      log.verbose('SDS-D', `Reusing existing auth token for ${webId}`);
    } else {
      // Create signed DPoP
      const dpop = await new SignJWT({
        htu: token_endpoint,
        htm: 'POST'
      })
        .setProtectedHeader({
          alg: 'PS256',
          typ: 'dpop+jwt',
          jwk: jwkPublicKey
        })
        .setIssuedAt()
        .setJti(randomUUID())
        .sign(privateKey);
      log.verbose('SDS-D', `Created signed DPoP proof`);

      // Get new auth token from token endpoint
      const tokens = await (await fetch(token_endpoint, {
          method: 'POST',
          headers: {
              'DPoP': dpop,
              'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: new URLSearchParams({
              grant_type: 'client_credentials',
              client_id,
              client_secret
          })
      })
      ).json();
      log.silly('SDS-D', 'Solid OIDC tokens:\n' + JSON.stringify(tokens));
      log.info('SDS-D', `Sucessfully logged in as ${webId}`);
      currentAuthToken = tokens['access_token'];
    }

    return currentAuthToken;
  }

  // Return actual middleware handler
  return async function delegationProxy(req, res, next) {
    log.verbose(`${req.rid}`, `Incoming request`);
    // Client is not authenticated with Solid OIDC
    // -> We are not responsible, just forward
    if(!req.headers['authorization'] || !req.headers['authorization'].startsWith('DPoP ') || !req.headers['dpop']) {
      log.info(`${req.rid}`, `No valid Solid OIDC headers, just forwarding request to ${req.originalUrl}`);
      forwardRequest(req, res);
      return;
    }

    // Get auth info from clients request
    const auth_token = req.headers['authorization'].replace('DPoP ','');
    const dpop_proof = req.headers['dpop'];

    try {
      const issuer = decodeJwt(auth_token)['iss'];
      // Invalid auth token
      if(!issuer) {
        res.status(403);
        log.warn(`${req.rid}`, `Auth token invalid: No issuer!`);
        res.send("Auth token invalid: No issuer!");
        return;
      }

      // Get public key of IdP used for signing the auth token
      const jwks_endpoint = (await (await fetch(issuer + '.well-known/openid-configuration')).json())['jwks_uri'];
      const jwks = await createRemoteJWKSet(new URL(jwks_endpoint));
      log.verbose(`${req.rid}`, `Retrieved signing keys from IdP's JWKs endpoint ${jwks_endpoint}`);

      // Verify access token with public key of IdP
      const { payload: payload_auth_token } = await jwtVerify(auth_token, jwks);
      log.verbose(`${req.rid}`, `Auth token signature verified`);

      // Get key the DPoP token should be signed with
      const client_key_thumbprint = payload_auth_token['cnf']['jkt']
      const client_public_key = await importJWK(decodeProtectedHeader(dpop_proof)['jwk']);

      // Check whether the DPoP signing key matches the auth token thumbprint
      if(await calculateJwkThumbprint(decodeProtectedHeader(dpop_proof)['jwk']) !== client_key_thumbprint) {
        log.warn(`${req.rid}`, `DPoP invalid: Thumbprint not matching signing key!`);
        res.send("DPoP invalid: Thumbprint not matching signing key!");
        res.sendStatus(403);
        return;
      }
      log.verbose(`${req.rid}`, `Verified that DPoP signature key match thumbprint in auth token`);

      // Check whether URI and method in the DPoP match the requested URI and method
      const { payload: payload_dpop_proof } = await jwtVerify(dpop_proof, client_public_key);
      // We do a trick here and make a HTTPS URI out of the HTTP URI we had to use for proxy reasons
      const requestUri = 'https://' + req.get('host') + req.path;
      if(payload_dpop_proof['htu'] !== requestUri || payload_dpop_proof['htm'] !== req.method) {
        log.warn(`${req.rid}`, `Auth token invalid: Requested method or URI does not match!`);
        res.send("Auth token invalid: Requested method or URI does not match!");
        res.sendStatus(403);
        return;
      }
      log.verbose(`${req.rid}`, `Verified that requested method and URI match auth token`);

      // We have an authenticated WebId \o/
      const webId = payload_auth_token['webid'];
      log.info(`${req.rid}`, `${webId} wants to send a ${req.method} request to ${requestUri}`);

      // Check whether the polices allow the request for the authenticated WebId
      let method;
      switch(req.method) {
        case 'GET':
          method = HttpMethod.GET;
          break;
        case 'POST':
          method = HttpMethod.POST;
          break;
        case 'PUT':
          method = HttpMethod.PUT;
          break;
        case 'POST':
          method = HttpMethod.POST;
          break;
      }
      if(!hasAccess(webId, requestUri, method)) {
        log.warn(`${req.rid}`, `Access denied by policies!`);
        res.send("Access denied by policies!");
        res.sendStatus(403);
        return;
      }

      // Create and sign a DPoP for the request
      const proxy_dpop = await new SignJWT({
        htu: payload_dpop_proof['htu'],
        htm: payload_dpop_proof['htm']
      })
      .setProtectedHeader({
        alg: 'PS256',
        typ: 'dpop+jwt',
        jwk: jwkPublicKey
      })
      .setIssuedAt()
      .setJti(randomUUID())
      .sign(privateKey);
      log.verbose(`${req.rid}`, `Created signed DPoP for request`);

      const serverRes = await fetch(payload_dpop_proof['htu'], {
        method: payload_dpop_proof['htm'],
        headers: {
            'DPoP': proxy_dpop,
            'Authorization': 'DPoP ' + await getCurrentAuthToken()
        }
      });
      log.verbose(`${req.rid}`, `Sent request, received response`);

      // Copy header and status to client response
      res.set(Object.fromEntries(serverRes.headers));
      res.status(serverRes.status);

      // Copy body to client response
      let reader = serverRes.body.getReader();
      let done = false
      let value = '';
      while(!done) {
        res.write(value);
        ({ value, done } = await reader.read());
      }
      res.end();
      log.verbose(`${req.rid}`, `Finished returning response`);
    } catch(error) {
      res.status(403);
      log.warn(`${req.rid}`, error);
      res.send(error);
      return;
    }
  }
}

const HttpMethod = {
  GET: 0,
  POST: 1,
  PUT: 2,
  DELETE: 3
}

/*
The SME Solid Pod contains policies like this:
  <#roleCEO> frog:hasAccess [
    http:mthd httpm:PUT ;
    http:uri <https://bank.solid.aifb.kit.edu/offer/1>
  ] .

and an organization ontology modeling which determines which WebId has which org:Role

Parameters:
  webId:  string
  uri: string
  method: HttpMethod 

Return:
  boolean
*/
async function hasAccess(webId, uri, method, session) {
  // TODO for Apoorva
  // for now:
  return webId == 'https://tom.solid.aifb.kit.edu/profile/card#me' && uri == 'https://bank.solid.aifb.kit.edu/credits/offers/7b49ef42-45ef-4d1b-9234-a6d3e9875c79' && method == HttpMethod.GET;
}

// Set up middleware
app.use(await delegationProxy(
  'https://sme.solid.aifb.kit.edu/profile/card#me',
  'https://solid.aifb.kit.edu',
  'delegation_proxy_4ae7b58d-3632-41f3-b495-7711c5ad4839',
  '43a227e4b303d1bb13ffc01fdec4ca9ec7120326684551e3878dbd50c2539abbb31c853fca6455ab43f34125e990f0a02fdb71a1765076a0c80577d2ac3d6e58'
));

export default app;