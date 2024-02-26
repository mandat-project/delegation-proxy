
const { SME_EMAIL, SME_PASSWORD, OIDC_NAME, OIDC_USER, POD_URL} = require('./constants');
const { calculateJWKThumbprint }  = require('./utils');
const express = require('express');
const { Session } = require('@inrupt/solid-client-authn-node');

const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

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

async function hasAccess(webId, uri, method) {
  // TODO for Apoorva
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

// Middleware for forwarding the PUT request to the Solid Pod authenticated as SME
const forwardRequestToPodAsSME = async (req, res, next, url) => {
  try {
    const { default: fetch } = await import('node-fetch');
    const podUrl = POD_URL;
    const method = req.method;
    // Forward the PUT request to the Solid Pod using the authenticated smeSession
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

// Set up middleware
app.use(express.text());
app.use(authenticateSME);

app.all('*', async (req, res, next) => {
  const path = req.originalUrl;
  console.log(req.method, "route from Postman:", path);

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
}, (req, res) => {
  const { podResponse } = req;
  res.send(podResponse);
});


// Start the server
app.listen(port, () => {
  console.log(`Delegation proxy listening at http://localhost:${port}`);
});

// done
// return just the pod response - done
// fix the PUT and GET response - done
// send triple in the request body - done
// Have few test cases for GET, PUT, POST, DELETE - partially done

// todo
// start the server before running the test case
// run series of test GET after PUT and assert the data
// delete the new resource
// proxy to authenticate TOM (library will validate the dpop token, starts with oidc(probably))
// check the authorization for TOM



// {
//   "email": "tom@sme.com",
//   "password": "tom42"
// }


