
const { SME_EMAIL, SME_PASSWORD, OIDC_NAME, OIDC_USER, POD_URL} = require('./constants');
const { calculateJWKThumbprint }  = require('./utils');
const express = require('express');
const { Session } = require('@inrupt/solid-client-authn-node');
const { Parser } = require('n3');

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

// https://github.com/rdfjs/N3.js
// const requestUri = 'https://' + req.get('host') + req.path;

async function checkSolidPodAccess(req, res, webId, uri, method) {
  const solidPodPolicies = await fetchSolidPodPolicies(req, res, webId);
  console.log("solidPodPolicies for ",webId, " ", solidPodPolicies)
    // Check if the role CEO has policies for the specified method
  const roleCEOPolicies = solidPodPolicies[method];

  // Check if the method exists and if the specified URI is allowed
  if (roleCEOPolicies && roleCEOPolicies.includes(uri)) {
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


function parseRdfDataForWebID(rdfData, webID) {
  const parsedPolicies = {};
  const accessTriples = rdfData.match(/frog:access\s*\[([^\]]*)\]/g);

  if (accessTriples) {
    for (const accessTriple of accessTriples) {
      const methodMatch = accessTriple.match(/frog:httpMethod\s*"([^"]+)"/);
      const uriMatch = accessTriple.match(/frog:uri\s*<([^>]+)>/);

      if (methodMatch && uriMatch) {
        const httpMethod = methodMatch[1];
        const uri = uriMatch[1];

        // Assuming the webID is specified in the RDF data either directly or using org:heldBy
        let roleWebIDMatch = accessTriple.match(/org:heldBy\s*<([^>]+)>/);
        let roleWebID = roleWebIDMatch ? roleWebIDMatch[1] : null;

        if (!roleWebID) {
          // Check if org:heldBy is specified directly outside of frog:access
          const directHeldByMatch = rdfData.match(/<[^>]+>\s+org:heldBy\s*<([^>]+)>/);
          roleWebID = directHeldByMatch ? directHeldByMatch[1] : null;
        }

        // Use a case-insensitive comparison for webID
        if (roleWebID && roleWebID.toLowerCase() === webID.toLowerCase()) {
          if (!parsedPolicies[httpMethod]) {
            parsedPolicies[httpMethod] = [];
          }

          parsedPolicies[httpMethod].push(uri);
        }
      }
    }
  }
  return parsedPolicies;
}



//todo: use n3 library to parse the RDF

// async function parseRdfDataForWebID(rdfData, webID) {
//   const parsedPolicies = {};
//
//   // Create a new N3 parser
//   const parser = new Parser();
//   const prefixes = {};
//
//   parser.parse(rdfData, (error, triple) => {
//     if (error) {
//       console.error('Error parsing RDF data:', error);
//       return;
//     }
//     if (
//       triple &&
//       triple.predicate.id === 'http://www.w3.org/ns/org#heldBy' &&
//       triple.object.id === webID
//     ) {
//       const roleUri = triple.subject;
//       const accessPolicies = findAccessPolicies(parser, rdfData, roleUri, prefixes);
//       Object.assign(parsedPolicies, accessPolicies);
//     }
//   });
//   return parsedPolicies;
// }

// function findAccessPolicies(parser, rdfData, roleUri, prefixes) {
//   const accessPolicies = {};
//
//   parser.parse(rdfData, (error, triple) => {
//     if (error) {
//       console.error('Error parsing RDF data:', error);
//       return;
//     }
//
//     if (
//       triple &&
//       triple.subject === roleUri &&
//       triple.predicate === `${prefixes.frog}access`
//     ) {
//       const methodTriple = findTripleWithPredicate(parser, rdfData, triple.object, `${prefixes.frog}httpMethod`);
//       const uriTriple = findTripleWithPredicate(parser, rdfData, triple.object, `${prefixes.frog}uri`);
//
//       if (methodTriple && uriTriple) {
//         const method = methodTriple.object.value.toUpperCase();
//         const uri = uriTriple.object.value;
//
//         // Add the access policy to the accessPolicies object
//         if (!accessPolicies[method]) {
//           accessPolicies[method] = [];
//         }
//         accessPolicies[method].push(uri);
//       }
//     }
//   });
//
//   return accessPolicies;
// }
//
// function findTripleWithPredicate(parser, rdfData, subject, predicate) {
//   let foundTriple = null;
//
//   // Parse the RDF data
//   parser.parse(rdfData, (error, triple) => {
//     if (error) {
//       console.error('Error parsing RDF data:', error);
//       return;
//     }
//
//     if (triple && triple.subject === subject && triple.predicate === predicate) {
//       foundTriple = triple;
//     }
//   });
//
//   return foundTriple;
// }


// Middleware for forwarding the PUT request to the Solid Pod authenticated as SME

// Set up middleware
app.use(express.text());
app.use(authenticateSME);

app.all('*', async (req, res, next) => {
  const path = req.originalUrl;
  console.log(req.method, "route from Postman:", path);

  const webId = 'https://tom.solid.aifb.kit.edu/profile/card#me';
  const uri = 'https://bank.solid.aifb.kit.edu/offer/1'

  //const webId = 'https://apoorva.solid.aifb.kit.edu/profile/card#me';
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


