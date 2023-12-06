const express = require('express');
const { Session } = require('@inrupt/solid-client-authn-node');

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
				email: 'info@sme.com',
				password: 'sme24',
				name: 'oidc-token'
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
    //req.authString = Buffer.from(`${id}:${secret}`).toString('base64');
    next();
  } catch (error) {
    console.error(`Error authenticating user: ${error.message}`);
    res.status(401).send('Authentication failed');
  }
};

// Middleware for forwarding the PUT request to the Solid Pod authenticated as SME
const forwardRequestToPodAsSME = async (req, res, next) => {
  try {
    const { default: fetch } = await import('node-fetch');
    const podUrl = 'https://bank.solid.aifb.kit.edu';
    // Forward the PUT request to the Solid Pod using the authenticated smeSession
    const response = await fetch(`${podUrl}/offer/1`, {
      method: 'PUT',
      headers: {
        authorization: `Basic ${Buffer.from(req.authString).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: JSON.stringify(req.body),
    });

    const { access_token: accessToken } = await response.json();

    req.podResponse = await response.text();
    next();
  } catch (error) {
    console.error(`Error forwarding PUT request to Solid Pod as SME: ${error.message}`);
    console.error('Response from Solid Pod:', error.response.data);
    res.status(500).send('Error forwarding PUT request to Solid Pod as SME');
  }
};

// Set up middleware
app.use(express.json());
app.use(authenticateSME);

// Route for user Tom to forward the request to the Solid Pod as SME
app.put('/offer/1', forwardRequestToPodAsSME, (req, res) => {
  const { podResponse } = req;
  console.log(podResponse)
  res.send('PUT request forwarded to Solid Pod as SME');
});

// Start the server
app.listen(port, () => {
  console.log(`Delegation proxy listening at http://localhost:${port}`);
});
