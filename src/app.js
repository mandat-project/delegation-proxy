import express from 'express';
import { exportJWK, SignJWT, generateKeyPair, jwtVerify, decodeJwt, decodeProtectedHeader, importJWK, createRemoteJWKSet, calculateJwkThumbprint } from 'jose';
import { randomUUID } from 'crypto';
import log from 'npmlog';
import ruid from 'express-ruid';
import { DataFactory, Parser, Store, Writer } from 'n3';
import cors from 'cors';
import process from 'process';
import bodyParser from 'body-parser';

const { namedNode } = DataFactory;

// Set log level
log.level = 'silly'

const app = express();

// Adding Express middleware for unique request id
app.use(ruid({
  setInContext: true,
  upBytes: 3,
  idMax: 9999,
  prefixRoot: '',
  prefixSeparator: ''
}));

// This function returns an Express.js middleware
async function reverseProxy(delegatorWebId, client_id, client_secret, pod_address, base_uri) {
  log.verbose('DDP', 'Starting DDP middleware');
  // Logging in with Solid OIDC

  // Helper for mapping Solid Pod URI to local Pod URI
  function uriToLocal(uri) {
    let url = new URL(uri);
    return new URL(url.pathname + url.hash, pod_address);
  }

  // Constructing local WebId to access profile document

  var idp = await getOIDCIssuer(delegatorWebId);
  if(idp.endsWith('/')) {
    idp = idp.substring(0, idp.length - 1);
  }

  log.verbose('DDP', `Logging in as ${delegatorWebId}`);
  // Create keypair for signing DPoPs
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwkPublicKey = await exportJWK(publicKey);
  jwkPublicKey.alg = 'RS256';

  // Find token endpoint of IdP
  const oidc_config = await (await fetch(idp + '/.well-known/openid-configuration')).json();
  const token_endpoint = oidc_config['token_endpoint'];
  log.verbose('DDP', `Found token endpoint ${token_endpoint}`);

  // Save the current auth token here
  var currentAuthToken = null;
  // For every outgoing request this function should be called to see if
  // the auth token is still valid and otherwise get a new one
  async function getCurrentAuthToken() {
    if(currentAuthToken && decodeJwt(currentAuthToken).exp > (Date.now() / 1000 + 60 * 9)) {
      // Still valid (plus one minute in the future), nothing to do
      log.verbose('DDP', `Reusing existing auth token for ${delegatorWebId}`);
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
      log.verbose('DDP', `Created signed DPoP proof`);
      log.silly(`DDP`, `DPoP: ${dpop}`);

      // Get new auth token from token endpoint
      const res = await fetch(token_endpoint, {
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
      if(res.ok) {
        const tokens = await res.json();
        log.silly('DDP', 'Solid OIDC tokens:\n' + JSON.stringify(tokens));
        log.info('DDP', `Sucessfully logged in as ${delegatorWebId}`);
        currentAuthToken = tokens['access_token'];
      } else {
        let errorMsg = await res.text();
        log.error(`DDP`, `Was not able to log in: ${errorMsg}`);
        throw new Error(errorMsg);
      }
    }

    return currentAuthToken;
  }

  async function getOIDCIssuer(delegatorWebId) {
    const profile = await fetch(uriToLocal(delegatorWebId), {
      headers: {
        'X-Forwarded-Host': new URL(delegatorWebId).hostname,
      	'X-Forwarded-Proto': 'https'
	}
    });
	let pt = await profile.text()

    const store = await parse(pt, delegatorWebId);
    const issuers = store.getObjects(namedNode(delegatorWebId), namedNode('http://www.w3.org/ns/solid/terms#oidcIssuer'));
    if(issuers.length != 1) {
      log.warn('Found ' + issuers.length + ' OIDC issuers in the profile document of ' + delegatorWebId + ', needed exactly one!');
    } else {
      log.verbose('DDP', 'Using OIDC issuer at ' + issuers[0].value + ' for authenticating the delegator');
    }
    return issuers[0].value;
  }

  async function makeAuthenticatedRequestToStore(uri, method, local = false) {
    return new Promise(async (resolve, reject) => {
      const store = new Store();
      const parser = new Parser({
        baseIRI: uri
      });

      // Create and sign a DPoP for the request
      const proxy_dpop = await new SignJWT({
        htu: uri,
        htm: method
      })
      .setProtectedHeader({
        alg: 'PS256',
        typ: 'dpop+jwt',
        jwk: jwkPublicKey
      })
      .setIssuedAt()
      .setJti(randomUUID())
      .sign(privateKey);

      const serverRes = await fetch(local ? uriToLocal(uri) : uri, {
        method: method,
        headers: {
            'DPoP': proxy_dpop,
            'Authorization': 'DPoP ' + await getCurrentAuthToken(),
            'X-Forwarded-Host': new URL(uri).hostname,
	    'X-Forwarded-Proto': 'https'
        }
      });
      if(!serverRes.ok) {
        let error = await serverRes.text();
        log.warn(`DDP`, `${method} request to ${uri} failed: ${error}`);
        reject(error);
      } else {
        parser.parse(await serverRes.text(), (error, quad) => {
          if(quad) {
            store.addQuad(quad);
          } else {
            resolve(store);
          }
        });
      }
    });
  }

  // Find all data registrations that are FacadeDataRegistrations
  let profileStore = await makeAuthenticatedRequestToStore(delegatorWebId, 'GET', true);
  let registrySets = profileStore.getObjects(namedNode(delegatorWebId), namedNode('http://www.w3.org/ns/solid/interop#hasRegistrySet'));
  if(registrySets.length != 1) {
    log.error(`DDP`, `${delegatorWebId} has ${registrySets.length} registry sets in their profile document but need exactly one!`);
    throw new Error(`${delegatorWebId} has ${registrySets.length} registry sets in their profile document but need exactly one!`);
  }
  let registrySetStore = await makeAuthenticatedRequestToStore(registrySets[0].value, 'GET', true);
  let dataRegistries = registrySetStore.getObjects(namedNode(registrySets[0].value), namedNode('http://www.w3.org/ns/solid/interop#hasDataRegistry')).map(nn => nn.value);
  let facadeDataRegistration = new Map();
  for(let dataRegistry of dataRegistries) {
    let dataRegistryStore = await makeAuthenticatedRequestToStore(dataRegistry, 'GET', true);
    let dataRegistrations = dataRegistryStore.getObjects(namedNode(dataRegistry), namedNode('http://www.w3.org/ns/ldp#contains')).map(nn => nn.value);
    for(let dataRegistration of dataRegistrations) {
      let dataRegistrationStore = await makeAuthenticatedRequestToStore(dataRegistration, 'GET', true);
      if(dataRegistrationStore.has(namedNode(dataRegistration), namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'), namedNode('http://example.org/vocab/datev/delegation#FacadeDataRegistration'))) {
        let shadowedUris = dataRegistrationStore.getObjects(namedNode(dataRegistration), namedNode('http://example.org/vocab/datev/delegation#shadowsRegistration')).map(nn => nn.value);
        let list = [];
        for(let shadowedUri of shadowedUris) {
          log.info(`DDP`, `${dataRegistration} shadows data registration at ${shadowedUri}`);
          list.push(shadowedUri);
        }
        facadeDataRegistration.set(dataRegistration, list);
      }
    }
  }

  // Get all the resources that are shadowed
  let facadeResources = new Map();
  let facadeContainers = new Map();
  for(let [key, value] of facadeDataRegistration.entries()) {
    let list = [];
    for(let l of value) {
      let shadowedStore = await makeAuthenticatedRequestToStore(l, 'GET', false);
      let shadowed = shadowedStore.getObjects(namedNode(l), namedNode('http://www.w3.org/ns/ldp#contains')).map(nn => [nn.value.replace(l, key), nn.value])
      shadowed.forEach(r => facadeResources.set(...r));
      list.push(...shadowed.map(s => s[0]));
    }
    facadeContainers.set(key, list)
  }

  log.silly(`DDP`, `Facaded resources: ${[...facadeResources.entries()]}`);
  log.silly(`DDP`, `Facaded containers: ${[...facadeContainers.entries()]}`);
  
  // Return actual middleware handler
  return async function reverseProxy(req, res, next) {
    log.verbose(`${req.rid}`, `Incoming request`);

    const requestUri = base_uri + req.originalUrl;

    // Check whether request URI is facaded
    if(facadeResources.has(requestUri)) {
      log.verbose(`${req.rid}`, `URI ${requestUri} is facade for ${facadeResources.get(requestUri)}`)
      // Get auth info from clients request
      if(req.headers['authorization'] && req.headers['dpop']) {
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
          if(payload_dpop_proof['htu'] !== requestUri || payload_dpop_proof['htm'] !== req.method) {
            log.warn(`${req.rid}`, `Auth token invalid: Requested method or URI does not match!`);
            res.status(403);
            res.send("Auth token invalid: Requested method or URI does not match!");
            return;
          }
          log.verbose(`${req.rid}`, `Verified that requested method and URI match auth token`);

          // We have an authenticated WebId \o/
          const delegateWebId = payload_auth_token['webid'];
          log.info(`${req.rid}`, `${delegateWebId} triggers a ${req.method} request to ${requestUri}`);

          // Create and sign a DPoP for the request
          const proxy_dpop = await new SignJWT({
            htu: facadeResources.get(requestUri),
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

          const reservedHeaderKeys = ['x-forwarded-host','x-forwarded-proto','server','set-cookie','upgrade','connection','host','authorization','dpop']
          const filteredHeaders = Object.keys(req.headers).filter(key => !reservedHeaderKeys.includes(key)).reduce((headers,key) => {headers[key]=req.headers[key]; return headers},{});

          const serverRes = await fetch(uriToLocal(facadeResources.get(requestUri)), {
            method: payload_dpop_proof['htm'],
            headers: {
                ...filteredHeaders,
                'DPoP': proxy_dpop,
                'Authorization': 'DPoP ' + await getCurrentAuthToken(),
                'X-Forwarded-Host': new URL(facadeResources.get(requestUri)).hostname,
                'X-Forwarded-Proto': 'https'
            },
            body: (!req.body || (typeof req.body === "object" && Object.keys(req.body).length==0)) ? undefined :req.body
          });

          log.verbose(`${req.rid}`, `Sent request, received response`);

          // Copy header and status to client response
          res.set(Object.fromEntries(serverRes.headers));
          res.status(serverRes.status);

          // Copy body to client response
          if (serverRes.body) {
            let reader = serverRes.body.getReader();
            let done = false
            let value = '';
            while(!done) {
              res.write(value);
              ({ value, done } = await reader.read());
            }
          }
          res.end();
          log.verbose(`${req.rid}`, `Finished returning response`);
        } catch(error) {
          res.status(403);
          log.warn(`${req.rid}`, error);
          res.send(error);
          return;
        }
      } else {
        // Forward unauthenticated facaded request
        const reservedHeaderKeys = ['x-forwarded-host','x-forwarded-proto','server','set-cookie','upgrade','connection','host','authorization','dpop']
        const filteredHeaders = Object.keys(req.headers).filter(key => !reservedHeaderKeys.includes(key)).reduce((headers,key) => {headers[key]=req.headers[key]; return headers},{});

        const serverRes = await fetch(uriToLocal(facadeResources.get(requestUri)), {
          method: payload_dpop_proof['htm'],
          headers: {
              ...filteredHeaders,
              'X-Forwarded-Host': new URL(facadeResources.get(requestUri)).hostname,
              'X-Forwarded-Proto': 'https'
          },
          body: (!req.body || (typeof req.body === "object" && Object.keys(req.body).length==0)) ? undefined :req.body
        });

        log.verbose(`${req.rid}`, `Sent request, received response`);

        // Copy header and status to client response
        res.set(Object.fromEntries(serverRes.headers));
        res.status(serverRes.status);

        // Copy body to client response
        if (serverRes.body) {
          let reader = serverRes.body.getReader();
          let done = false
          let value = '';
          while(!done) {
            res.write(value);
            ({ value, done } = await reader.read());
          }
        }
        res.end();
        log.verbose(`${req.rid}`, `Finished returning response`);
      }
    } else if(facadeContainers.has(requestUri)) {
      // check if facaded container
      log.verbose(`${req.rid}`, `URI ${requestUri} is facade container`)

      if(req.headers['authorization'] && req.headers['dpop']) {
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
          if(payload_dpop_proof['htu'] !== requestUri || payload_dpop_proof['htm'] !== req.method) {
            log.warn(`${req.rid}`, `Auth token invalid: Requested method or URI does not match!`);
            res.status(403);
            res.send("Auth token invalid: Requested method or URI does not match!");
            return;
          }
          log.verbose(`${req.rid}`, `Verified that requested method and URI match auth token`);

          // We have an authenticated WebId \o/
          const delegateWebId = payload_auth_token['webid'];
          log.info(`${req.rid}`, `${delegateWebId} triggers a ${req.method} request to ${requestUri}`);

          // Create and sign a DPoP for the request
          const proxy_dpop = await new SignJWT({
            htu: uriToLocal(requestUri),
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

          const reservedHeaderKeys = ['x-forwarded-host','x-forwarded-proto','server','set-cookie','upgrade','connection','host','authorization','dpop']
          const filteredHeaders = Object.keys(req.headers).filter(key => !reservedHeaderKeys.includes(key)).reduce((headers,key) => {headers[key]=req.headers[key]; return headers},{});

          const serverRes = await fetch(uriToLocal(requestUri), {
            method: payload_dpop_proof['htm'],
            headers: {
                ...filteredHeaders,
                'DPoP': proxy_dpop,
                'Authorization': 'DPoP ' + await getCurrentAuthToken(),
                'X-Forwarded-Host': new URL(requestUri).hostname,
                'X-Forwarded-Proto': 'https'
            },
            body: (!req.body || (typeof req.body === "object" && Object.keys(req.body).length==0)) ? undefined :req.body
          });

          log.verbose(`${req.rid}`, `Sent request, received response`);

          // Copy header and status to client response
          res.set(Object.fromEntries(serverRes.headers));
          res.status(serverRes.status);

          // Parse body to add triples
          let store = await parse(await serverRes.text(), requestUri);
          facadeContainers.get(requestUri).forEach(cr => store.addQuad(namedNode(requestUri), namedNode('http://www.w3.org/ns/ldp#contains'), namedNode(cr)))
          let writer = new Writer();
          writer.addQuads(store.getQuads());
          writer.end((error, result) => {
            res.send(result)
          });

          log.verbose(`${req.rid}`, `Finished returning response`);
        } catch(error) {
          res.status(403);
          log.warn(`${req.rid}`, error);
          res.send(error);
          return;
        }
      } else {
        // Forward unauthenticated facaded request
        const reservedHeaderKeys = ['x-forwarded-host','x-forwarded-proto','server','set-cookie','upgrade','connection','host','authorization','dpop']
        const filteredHeaders = Object.keys(req.headers).filter(key => !reservedHeaderKeys.includes(key)).reduce((headers,key) => {headers[key]=req.headers[key]; return headers},{});

        const serverRes = await fetch(uriToLocal(facadeResources.get(requestUri)), {
          method: payload_dpop_proof['htm'],
          headers: {
              ...filteredHeaders,
              'X-Forwarded-Host': new URL(facadeResources.get(requestUri)).hostname,
              'X-Forwarded-Proto': 'https'
          },
          body: (!req.body || (typeof req.body === "object" && Object.keys(req.body).length==0)) ? undefined :req.body
        });

        log.verbose(`${req.rid}`, `Sent request, received response`);

        // Copy header and status to client response
        res.set(Object.fromEntries(serverRes.headers));
        res.status(serverRes.status);

        // Copy body to client response
        if (serverRes.body) {
          let reader = serverRes.body.getReader();
          let done = false
          let value = '';
          while(!done) {
            res.write(value);
            ({ value, done } = await reader.read());
          }
        }
        res.end();
        log.verbose(`${req.rid}`, `Finished returning response`);
      }
    } else {
      // if not in facade, just forward
      log.verbose(`${req.rid}`, `URI ${requestUri} is not facaded, just forwarding request`)
      try {
        const reservedHeaderKeys = ['x-forwarded-host','x-forwarded-proto','server','set-cookie','upgrade','connection','host','authorization','dpop']
        const filteredHeaders = Object.keys(req.headers).filter(key => !reservedHeaderKeys.includes(key)).reduce((headers,key) => {headers[key]=req.headers[key]; return headers},{});

        const serverRes = await fetch(uriToLocal(requestUri), {
          method: req.method,
          headers: {
              ...filteredHeaders,
              'DPoP': req.headers['dpop'],
              'Authorization': req.headers['authorization'],
              'X-Forwarded-Host': new URL(requestUri).hostname,
              'X-Forwarded-Proto': 'https'
          },
          body: (!req.body || (typeof req.body === "object" && Object.keys(req.body).length==0)) ? undefined :req.body
        });

        log.verbose(`${req.rid}`, `Sent request, received response`);

        // Copy header and status to client response
        res.set(Object.fromEntries(serverRes.headers));
        res.status(serverRes.status);

        // Copy body to client response
        if (serverRes.body) {
          let reader = serverRes.body.getReader();
          let done = false
          let value = '';
          while(!done) {
            res.write(value);
            ({ value, done } = await reader.read());
          }
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
}

async function parse(rdfString, baseUri) {
  return new Promise((resolve, reject) => {
    const parser = new Parser({
      baseIRI: baseUri
    });
    const store = new Store();
    parser.parse(rdfString, (error, quad) => {
      if(error) {
        reject(error);
        return;
      }
      if(quad) {
        store.add(quad);
      } else {
        resolve(store);
      }

    })
  });
}

app.use(cors())

// body parser must be set before middleware
app.use(bodyParser.raw({
  inflate: true,
  limit: '100Mb',
  type: '*/*'
}));

// Set up middleware
app.use(await reverseProxy(
  process.env.DELEGATOR_WEB_ID,
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.POD_ADDRESS,
  process.env.BASE_URI
));

export default app;
