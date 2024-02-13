const { SME_EMAIL, SME_PASSWORD, OIDC_NAME } = require('./constants');

const express = require('express');
const { Session } = require('@inrupt/solid-client-authn-node');

const N3 = require('n3');

const app = express();
const port = 3000;

// Middleware for authenticating the SME
const authenticateSME = async (req, res, next) => {
  try {
    const oidcIssuer = 'https://solid.aifb.kit.edu/';
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
    const podUrl = 'https://bank.solid.aifb.kit.edu';
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

app.all('*', (req, res, next) => {
  const path = req.originalUrl;
  console.log("Request Body: ", req.body)
  console.log(req.method, "route from Postman:", path);
  forwardRequestToPodAsSME(req, res, next, path);
}, (req, res) => {
  const { podResponse } = req;
  res.send(podResponse);
});


// Start the server
app.listen(port, () => {
  console.log(`Delegation proxy listening at http://localhost:${port}`);
});

//todo:
// creturn just the pod response.
// fix the PUT and GET response
// Have few test cases for GET, PUT, POST, DELETE
// proxy to authenticate TOM (library will validate the dpop token, starts with oidc(probably))
// check the authorization for TOM



// {
//   "email": "tom@sme.com",
//   "password": "tom42"
// }
