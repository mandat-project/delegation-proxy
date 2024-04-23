
const { SME_EMAIL, SME_PASSWORD, OIDC_NAME, OIDC_USER, POD_URL, POD_URL_TEST} = require('./constants');
const { calculateJWKThumbprint }  = require('./utils');
const express = require('express');
const { Session } = require('@inrupt/solid-client-authn-node');
const N3 = require('n3');
const { DataFactory } = N3;
const { namedNode} = DataFactory;

const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

const HttpMethod = {
  GET: 0,
  POST: 1,
  PUT: 2,
  DELETE: 3
}

// Middleware for authenticating the SME
const authenticateSME = async (req, res, next) => {
  try {
    const oidcIssuer = OIDC_USER;
    const response = await fetch(oidcIssuer + 'idp/credentials/', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				email: SME_EMAIL,
				password: SME_PASSWORD,
				name: OIDC_NAME
			})
		});

    const { id, secret } = await response.json();
    // Authenticate using solid-client-authn-node
    const  smeSession = new Session()
    await smeSession.login({
      oidcIssuer: oidcIssuer,
      clientId: id,
      clientSecret: secret,
    });
    req.smeSession = smeSession;
    req.authString = `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;
    next();
  } catch (error) {
    console.error(`Error authenticating user: ${error.message}`);
    res.status(401).send('Authentication failed');
  }
};

const forwardRequestToPodAsSME = async (req, res, next, url) => {
  try {
    const { default: fetch } = await import('node-fetch');
    const podUrl = POD_URL;
    const method = req.method;
    const podTestUrl = POD_URL_TEST
    const requestOptions = {
      method: method,
      headers: {'content-type':req.headers['content-type']},
    };
    if (method === 'PUT' || method === 'POST') {
      requestOptions.body = req.body
    }
    const pod_response = await req.smeSession.fetch(`${podUrl}${url}`, requestOptions);

    if (method === 'GET') {
      req.podResponse = await pod_response.text();
    }
    else {
      req.podResponse = await pod_response;
    }
    next();
  } catch (error) {
    console.error(`Error forwarding PUT request to Solid Pod as SME: ${error.message}`);
    console.error('Response from Solid Pod:', error.response);
    res.status(500).send('Error forwarding PUT request to Solid Pod as SME');
  }
};

async function hasAccess(req, res, webId, uri, method) {
  // TODO for Apoorva
  console.log("URI to check access", uri)
  return await checkSolidPodAccess(req, res, webId, uri, method);
}

async function checkSolidPodAccess(req, res, webId, uri, method) {
  const solidPodPolicies = await fetchSolidPodPolicies(req, res, webId);
  console.log("solidPodPolicies ", solidPodPolicies)
    // Check if the role CEO has policies for the specified method
  const roleCEOPolicies = solidPodPolicies[webId];
  // Check if the method exists and if the specified URI is allowed
  if (roleCEOPolicies && (roleCEOPolicies[method].includes(uri))) {
    return true; // Access granted
  }

  return false; // Access denied
}


async function fetchSolidPodPolicies(req, res, webId) {
  const podEndpoint = 'https://sme.solid.aifb.kit.edu/organization/bank.ttl';
  const sme_response = await req.smeSession.fetch(`${podEndpoint}`);
  const rdfData = await sme_response.text();
  // Parse RDF data
  console.log(rdfData)
  const solidPodPolicies = parseRdfDataForWebID(rdfData, webId);
  return solidPodPolicies
}


async function parseRdfDataForWebID(rdfData, webId) {
  const store = new N3.Store()
  const parser = new N3.Parser();
  try {
    const  parsedRdf = parser.parse(rdfData);
    store.addQuads(parsedRdf)
  } catch (err) {
    console.error('Error parsing RDF data:', err);
    return;
  }

  const accessPolicies = {};
  for (const quad of store.getSubjects(namedNode('http://www.w3.org/ns/org#heldBy'),
      namedNode(webId))){
    const post = quad.id;
    const role = store.getObjects(namedNode(post), namedNode('http://www.w3.org/ns/org#role'))[0].id

    const accessQuads = store.getObjects(namedNode(role), namedNode('https://solid.ti.rw.fau.de/public/ns/frog#access'))
    for (const accessQuad of accessQuads) {
      const method = store.getObjects(accessQuad, namedNode('https://solid.ti.rw.fau.de/public/ns/frog#httpMethod'))[0].id
      const uri = store.getObjects(accessQuad, namedNode('https://solid.ti.rw.fau.de/public/ns/frog#uri'))[0].id

      const method_literal = method.slice(1, -1)

      if (!accessPolicies[webId]) {
        accessPolicies[webId] = {};
      }
      if (!accessPolicies[webId][method_literal]) {
        accessPolicies[webId][method_literal] = [];
      }
      accessPolicies[webId][method_literal].push(uri);
    }
  }
  return accessPolicies;
}

// Middleware for forwarding the PUT request to the Solid Pod authenticated as SME

// Set up middleware
app.use(express.text());
app.use(authenticateSME);

app.all('*', async (req, res, next) => {
  const path = req.originalUrl;
  console.log(req.method, "route from Postman:", path);

  const webId = 'https://tom.solid.aifb.kit.edu/profile/card#me';
  const uri = 'https://bank.solid.aifb.kit.edu/offer/1'

  // const webId = 'https://apoorva.solid.aifb.kit.edu/profile/card#me';
  const accessGranted = await hasAccess(req, res, webId, uri, req.method);
  console.log('Access Granted:', accessGranted);
  if (accessGranted) {
    const accessToken = req.headers['authorization'].replace('DPoP ', '');
    const dpopProofFromRequest = req.headers['dpop'];

    const decodedDPoPProof = jwt.decode(dpopProofFromRequest, {complete: true});
    const decodedAccessToken = jwt.decode(accessToken, {complete: true});

    const thumbprint = calculateJWKThumbprint(decodedDPoPProof.header.jwk);

    if (decodedAccessToken.payload.cnf.jkt === thumbprint) {
      await forwardRequestToPodAsSME(req, res, next, path);
    }
    else {
      res.status(401).json({ message: 'Invalid client for this access token' });
    }
  }
  else {
    res.status(403).json({ message: 'Access forbidden' });
  }

}, (req, res) => {
  const { podResponse } = req;
  res.send(podResponse);
});


// Start the server
function main() {
  const port = 3000; // Specify the port you want to listen on
  app.listen(port, () => {
    console.log(`Delegation proxy listening at http://localhost:${port}`);
  });
}

module.exports = main;

// Call the main function
main();


