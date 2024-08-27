import express from 'express';
import { exportJWK, SignJWT, generateKeyPair, jwtVerify, decodeJwt, decodeProtectedHeader, importJWK, createRemoteJWKSet, calculateJwkThumbprint } from 'jose';
import { randomUUID } from 'crypto';
import log from 'npmlog';
import ruid from 'express-ruid';
import { DataFactory, Parser, Store, Writer } from 'n3';
import cors from 'cors';
import process from 'process';
import bodyParser from 'body-parser';

const { literal, namedNode, quad } = DataFactory;

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

// This function returns an Express.js middleware
async function reverseProxy(delegatorWebId, client_id, client_secret, facadeRegistryUri) {
  log.verbose('SDS-D', 'Starting SDS-D middleware');
  // Logging in with Solid OIDC

  var idp = await getOIDCIssuer(delegatorWebId);
  if(idp.endsWith('/')) {
    idp = idp.substring(0, idp.length - 1);
  }

  log.verbose('SDS-D', `Logging in as ${delegatorWebId}`);
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
      log.verbose('SDS-D', `Reusing existing auth token for ${delegatorWebId}`);
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
      log.info('SDS-D', `Sucessfully logged in as ${delegatorWebId}`);
      currentAuthToken = tokens['access_token'];
    }

    return currentAuthToken;
  }

  async function getOIDCIssuer(delegatorWebId) {
    const profile = await fetch(delegatorWebId);
    const store = await parse(await profile.text(), delegatorWebId);
    const issuers = store.getObjects(namedNode(delegatorWebId), namedNode('http://www.w3.org/ns/solid/terms#oidcIssuer'));
    if(issuers.length != 1) {
      log.warn('Found ' + issuers.length + ' OIDC issuers in the profile document of ' + delegatorWebId + ', needed exactly one!');
    } else {
      log.verbose('SDS-D', 'Using OIDC issuer at ' + issuers[0].value + ' for authenticating the delegator');
    }
    return issuers[0].value;
  }

  async function getLoggingContainer(delegatorWebId) {
    const profile = await fetch(delegatorWebId);
    const store = await parse(await profile.text(), delegatorWebId);
    const containers = store.getObjects(namedNode(delegatorWebId), namedNode('https://www.example.org/logs#loggingContainer'));
    if(containers.length != 1) {
      log.warn('Found ' + containers.length + ' logging containers in the profile document of ' + delegatorWebId + ', needed exactly one!');
    } else {
      log.verbose('SDS-D', 'Using logging container at ' + containers[0].value);
    }
    return containers[0].value;
  }

  async function sendLogs(rqid, loggingStore, loggingContainer) {
    return new Promise((resolve, reject) => {
      const writer = new Writer();
      writer.addQuads(loggingStore.getQuads());
      writer.end(async (error, result) => {
        if(error) {
          reject(error);
        } else {
          const proxy_dpop = await new SignJWT({
            htu: loggingContainer,
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

          const serverRes = await fetch(loggingContainer, {
            method: 'POST',
            headers: {
                'DPoP': proxy_dpop,
                'Authorization': 'DPoP ' + await getCurrentAuthToken()
            },
            body: result
          });
          if(serverRes.status == 201) {
            log.verbose(rqid, 'Created new log entry at ' + serverRes.headers.get('Location')) ;
          } else {
            log.warn(rqid, 'Could not create new log entry: ' + serverRes.status + ' ' + serverRes.statusText)
          }
        }
      });
    })
  }

  async function logIncomingRequest(store, method, uri, delegateWebId, time) {
    store.addQuads([
      quad(namedNode('#primaryRequest'), namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'), namedNode('http://www.w3.org/ns/prov#Entity')),
      quad(namedNode('#primaryRequest'), namedNode('http://www.w3.org/2011/http#method'), namedNode('http://www.w3.org/2011/http-methods#' + method)),
      quad(namedNode('#primaryRequest'), namedNode('http://www.w3.org/2011/http#requestUri'), namedNode(uri)),
      quad(namedNode('#primaryRequest'), namedNode('http://www.w3.org/ns/prov#wasGeneratedBy'), namedNode(delegateWebId)), //has prov:Activity as range...?
      quad(namedNode('#primaryRequest'), namedNode('http://www.w3.org/ns/prov#wasAttributedTo'), namedNode(delegateWebId)),
      quad(namedNode('#primaryRequest'), namedNode('http://www.w3.org/ns/prov#generatedAtTime'), literal(time, namedNode('http://www.w3.org/2001/XMLSchema#dateTime'))),
    ])
  }

  async function logRDPActivity(store, delegateWebId, time, primaryEntity, policyResult) {
    store.addQuads([
      quad(namedNode('#RDPActivity'), namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'), namedNode('http://www.w3.org/ns/prov#Activity')),
      quad(namedNode('#RDPActivity'), namedNode('http://www.w3.org/ns/prov#startedAtTime'), literal(time, namedNode('http://www.w3.org/2001/XMLSchema#dateTime'))),
      quad(namedNode('#RDPActivity'), namedNode('http://www.w3.org/ns/prov#wasAssociatedWith'), namedNode(delegateWebId)),
      quad(namedNode('#RDPActivity'), namedNode('http://www.w3.org/ns/prov#wasStartedBy'), namedNode(primaryEntity)), 
      
      //missing: which policy was evaluated
      quad(namedNode('#RDPActivity'), namedNode('https://www.example.org/rdpVocab#policyEvaluation'), literal(policyResult, namedNode('http://www.w3.org/2001/XMLSchema#boolean'))), //connect to policy?
    ])
  }
  
  async function logRDPActivityEndTime(store, activityUri, endTime) {
    store.addQuads([
      quad(namedNode(activityUri), namedNode('http://www.w3.org/ns/prov#endedAtTime'), literal(endTime, namedNode('http://www.w3.org/2001/XMLSchema#dateTime'))),
    ])
  }

  async function logRDPRequest(store, method, uri, delegatorWebId, time) {
    store.addQuads([
      quad(namedNode('#RDPActivity'), namedNode('http://www.w3.org/ns/prov#generated'), namedNode('#secondaryRequest')),

      quad(namedNode('#secondaryRequest'), namedNode('http://www.w3.org/1999/02/22-rdf-syntax-ns#type'), namedNode('http://www.w3.org/ns/prov#Entity')),
      quad(namedNode('#secondaryRequest'), namedNode('http://www.w3.org/2011/http#method'), namedNode('http://www.w3.org/2011/http-methods#' + method)),
      quad(namedNode('#secondaryRequest'), namedNode('http://www.w3.org/2011/http#requestUri'), namedNode(uri)),
      quad(namedNode('#secondaryRequest'), namedNode('http://www.w3.org/ns/prov#wasGeneratedBy'), namedNode("#RDPActivity")),
      quad(namedNode('#secondaryRequest'), namedNode('http://www.w3.org/ns/prov#wasAttributedTo'), namedNode(delegatorWebId)), //now as delegator
      quad(namedNode('#secondaryRequest'), namedNode('http://www.w3.org/ns/prov#generatedAtTime'), literal(time, namedNode('http://www.w3.org/2001/XMLSchema#dateTime'))),
    ])
  }

  async function makeAuthenticatedRequestToStore(uri, method) {
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

      const serverRes = await fetch(uri, {
        method: method,
        headers: {
            'DPoP': proxy_dpop,
            'Authorization': 'DPoP ' + await getCurrentAuthToken()
        }
      });
      parser.parse(await serverRes.text(), (error, quad) => {
        if(quad) {
          store.addQuad(quad);
        } else {
          resolve(store);
        }
      });
    });
  }

  const loggingContainer = await getLoggingContainer(delegatorWebId);

  // Check which resources we have to facade
  let facadeRegistryStore = await makeAuthenticatedRequestToStore(facadeRegistryUri, 'GET');
  let toFacade = facadeRegistryStore.getObjects(null, namedNode('http://example.org/vocab/datev/delegation#shadowsRegistration')).map(nn => nn.value);
  let facade = new Map();
  for(let tF of toFacade) {
    let tFStore = await makeAuthenticatedRequestToStore(tF, 'GET');
    tFStore.getObjects(null, namedNode('http://www.w3.org/ns/ldp#contains')).map(nn => [nn.value.replace(tF, facadeRegistryUri), nn.value]).forEach(r => facade.set(...r));
  }
  
  // Return actual middleware handler
  return async function reverseProxy(req, res, next) {
    const loggingStore = new Store();
    log.verbose(`${req.rid}`, `Incoming request`);

    // We do a trick here and make a HTTPS URI out of the HTTP URI we had to use for proxy reasons
    const host = req.query['host'];
    if(!host) {
      log.warn('Client did not specify "host" query parameter!')
      res.status(400);
      res.send('No "host" query parameter specified!');
      return;
    }
    const requestUri = 'https://' + host;

    // Check whether request URI is facaded
    if(facade.has(requestUri)) {
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
        log.info(`${req.rid}`, `${delegateWebId} wants to send a ${req.method} request to ${requestUri}`);

        // Create and sign a DPoP for the request
        const proxy_dpop = await new SignJWT({
          htu: facade.get(requestUri),
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

        const serverRes = await fetch(facade.get(requestUri), {
          method: payload_dpop_proof['htm'],
          headers: {
              ...filteredHeaders,
              'DPoP': proxy_dpop,
              'Authorization': 'DPoP ' + await getCurrentAuthToken()
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
      // if not in facade, just forward
      console.log(requestUri)
      console.log(facade);
      try {
        const reservedHeaderKeys = ['x-forwarded-host','x-forwarded-proto','server','set-cookie','upgrade','connection','host','authorization','dpop']
        const filteredHeaders = Object.keys(req.headers).filter(key => !reservedHeaderKeys.includes(key)).reduce((headers,key) => {headers[key]=req.headers[key]; return headers},{});

        const serverRes = await fetch(payload_dpop_proof['htu'], {
          method: payload_dpop_proof['htm'],
          headers: {
              ...filteredHeaders,
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

const HttpMethod = {
  GET: 0,
  POST: 1,
  PUT: 2,
  DELETE: 3
}

async function hasAccess(delegatorWebId, delegateWebId, uri, method, session) {
  const profile = await fetch(delegatorWebId);
  const quads = await parse(await profile.text(), delegatorWebId);
  return quads.has(quad(namedNode(delegatorWebId), namedNode('http://www.w3.org/ns/org#hasMember'), namedNode(delegateWebId)));
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
  'https://sme.solid.aifb.kit.edu/businessAssessments/businessAssessment/'
));

export default app;
