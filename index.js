const {
  ID,
  SECRET,
  OIDC_USER,
  POD_URL,
  POD_URL_TEST,
  POD_WORKFLOW_URL,
  POD_FINANCE_URL,
  POD_ASSET_URL,
  POD_BANK_URL,
  POD_ACTIVITIES_URL,
  FINANCE_LEADER_MEMBERSHIP_URL,
  FINANCE_LEADER_MEMBERSHIP_URL_OPEN,
  FINANCE_LEADER_MEMBERSHIP_URL_NA,
  SIGNATURE_URL
} = require('./constants');
const fs = require('fs');
const path = require('path');
const { calculateJWKThumbprint }  = require('./utils');
const express = require('express');
const { Session, getSessionFromStorage} = require('@inrupt/solid-client-authn-node');
const N3 = require('n3');
const { DataFactory } = N3;
const { namedNode, quad} = DataFactory;

const { n3reasoner } = require('eyereasoner');

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
    const id = ID
    const secret = SECRET
    // Authenticate using solid-client-authn-node
    const  smeSession = new Session()
    await smeSession.login({
      oidcIssuer: oidcIssuer,
      clientId: id,
      clientSecret: secret
    });
    req.smeSession = smeSession;
    req.authString = `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;
    next();
  } catch (error) {
    console.error(`Error authenticating user: ${error.message}`);
    res.status(401).send('Authentication failed');
  }
};

// Function to merge Turtle files
async function mergeTurtleData(turtleDataArray) {
  const store = new N3.Store();
  const parser = new N3.Parser();
  const prefixes = {};

  try {
    // Loop through each Turtle data, parse the contents, then add to the store
    for (const turtleData of turtleDataArray) {
      const quads = parser.parse(turtleData);

      // Extract and store prefixes
      const parsedPrefixes = parser._prefixes; // Note: _prefixes is a private field in the N3 parser
      Object.assign(prefixes, parsedPrefixes); // Merge with existing prefixes

      store.addQuads(quads);
    }

    // Serialize the store into a single Turtle string
    const writer = new N3.Writer({ format: 'Turtle' });
    writer.addPrefixes(prefixes);
    store.forEach((quad) => writer.addQuad(quad));

    return new Promise((resolve, reject) => {
      writer.end((error, result) => {
        if (error) return reject(error);
        resolve(result);
      });
    });
  } catch (err) {
    console.error('Error merging Turtle data:', err);
    throw err;
  }
}

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
  const solidPodActivity = await fetchSolidPodInfo(req, res, webId, POD_ACTIVITIES_URL);
  const solidPodWorkflow = await fetchSolidPodInfo(req, res, webId, POD_WORKFLOW_URL);
  const solidPodFinance = await fetchSolidPodInfo(req, res, webId, POD_FINANCE_URL);
  const solidPodAsset = await fetchSolidPodInfo(req, res, webId, POD_ASSET_URL);
  const financeLeaderMembership = await fetchSolidPodInfo(req, res, webId, FINANCE_LEADER_MEMBERSHIP_URL);
  const financeLeaderMembershipNA = await fetchSolidPodInfo(req, res, webId, FINANCE_LEADER_MEMBERSHIP_URL_NA);
  const financeLeaderMembershipOpen = await fetchSolidPodInfo(req, res, webId, FINANCE_LEADER_MEMBERSHIP_URL_OPEN);
  const signatureInstances = await fetchSolidPodInfo(req, res, webId, SIGNATURE_URL);

  // Store the fetched Turtle data into an array
  const turtleDataArray = [
    solidPodActivity,
    solidPodWorkflow,
    solidPodFinance,
    solidPodAsset,
    financeLeaderMembership,
    signatureInstances
  ];

  // Merge the Turtle data
  const mergedTurtleString = await mergeTurtleData(turtleDataArray);

  const workflowInstancesRulesPath = path.join(__dirname, '/rules/workflow_rules.n3');
  const activitiesInstancesRules = fs.readFileSync(workflowInstancesRulesPath, 'utf-8');
  const  activities_datastring = `${mergedTurtleString}\n${activitiesInstancesRules}`;
// The result of the query (as a string)
  const finalDataString = await n3reasoner(activities_datastring);

  // console.log("N3 parser output:", finalDataString)
  const workflowApprovals = await parseApprovalStatus(finalDataString)
  console.log("Approvals: ", workflowApprovals)
  const workflowData = await fetchWorkflowData(req, res, webId);
  console.log("workflowData: ", workflowData)
  const MembershipRoles = new Set();
  for (const workflow of workflowData) {
    if (workflowApprovals[workflow['workflowInstance']] === 'approved') {
      if (workflowApprovals[workflow['workflowInstance']]) {
        MembershipRoles.add(workflow['MembershipRole']);
      } else {
        console.log("workflowInstance is not present in the Approved workflows");
      }
    }
  }
  const policies = await checkSolidPodAccess(req, res, webId, uri, method, MembershipRoles);
  console.log("URL policy: ", policies)
  return policies
  // todo by Apoorva:
  // 1. Handle multiple memberships
  // 2. How to we get the URLS
  // 3. Refactor the code and add comments
  // 4. Test for Non approval and open use case
  // 5. Test for another webID with different policies
}

async function fetchSolidPodInfo(req, res, containerUrl) {
  // Fetch the container's contents
  const sme_response = await req.smeSession.fetch(containerUrl);
  const rdfData = await sme_response.text();

  // Parse the RDF to find contained Turtle files
  const parser = new Parser();
  const store = new N3.Store();
  store.addQuads(parser.parse(rdfData));

  // Find all contained resources using ldp:contains
  const ldpContains = store.getQuads(null, namedNode('http://www.w3.org/ns/ldp#contains'), null, null);

  // Filter and fetch Turtle files
  const turtleFiles = [];
  for (const quad of ldpContains) {
    const fileUrl = quad.object.value;
    if (fileUrl.endsWith('.ttl')) {
      // Fetch Turtle file content
      const fileResponse = await req.smeSession.fetch(fileUrl);
      const fileData = await fileResponse.text();
      turtleFiles.push(fileData);
    }
  }

  // Merge all fetched Turtle data
  const mergedTurtleString = await mergeTurtleData(turtleFiles);

  return mergedTurtleString;
}

async function parseApprovalStatus(rdfData) {
  const store = new N3.Store();
  const parser = new N3.Parser();
  const approvalStatusDict = {};

  try {
    // Parse the RDF data and add it to the store
    const parsedRdf = parser.parse(rdfData);
    store.addQuads(parsedRdf);
  } catch (err) {
    console.error('Error parsing RDF data:', err);
    return {};
  }

  // Define the frog:approval predicate URI
  const approvalPredicate = namedNode('https://solid.ti.rw.fau.de/public/ns/frog#approval');
  const approvedNode = namedNode('https://solid.ti.rw.fau.de/public/ns/frog#approved');
  const notApprovedNode = namedNode('https://solid.ti.rw.fau.de/public/ns/frog#notApproved');

  // Get all unique subjects
  const subjects = [...new Set(store.getQuads(null, approvalPredicate, null, null).map(quad => quad.subject.value))];

  subjects.forEach(subject => {
    const approvalQuads = store.getQuads(namedNode(subject), approvalPredicate, null, null);

    if (approvalQuads.length === 0) {
      approvalStatusDict[subject] = 'open';
    } else {
      const approvalQuad = approvalQuads[0];
      if (approvalQuad.object.equals(approvedNode)) {
        approvalStatusDict[subject] = 'approved';
      } else if (approvalQuad.object.equals(notApprovedNode)) {
        approvalStatusDict[subject] = 'not approved';
      }
    }
  });

  return approvalStatusDict;
}

async function fetchWorkflowData(req, res, webId) {
  const podEndpoint = FINANCE_LEADER_MEMBERSHIP_URL;
  const sme_response = await req.smeSession.fetch(`${podEndpoint}`);
  const rdfData = await sme_response.text();
  // Parse RDF data
  const workflows = parseworkflowWebID(rdfData, webId);
  return workflows
}

// async function fetchSolidPodInfo(req, res, webId, podEndpoint) {
//   const sme_response = await req.smeSession.fetch(`${podEndpoint}`);
//   const rdfData = await sme_response.text();
//   return rdfData
// }

async function checkSolidPodAccess(req, res, webId, uri, method, MembershipRole) {
  const solidPodPolicies = await fetchSolidPodPolicies(req, res, webId, MembershipRole);
  console.log("solidPodPolicies ", solidPodPolicies)
    // Check if the role has policies for the specified method
  const policies = solidPodPolicies[webId];
  // Check if the method exists and if the specified URI is allowed
  if (policies && (policies[method].includes(uri))) {
    return true; // Access granted
  }
  return false; // Access denied
}


async function fetchSolidPodPolicies(req, res, webId, MembershipRole) {
  const podEndpoint = POD_FINANCE_URL;
  const sme_response = await req.smeSession.fetch(`${podEndpoint}`);
  const rdfData = await sme_response.text();
  // Parse RDF data
  const solidPodPolicies = parseRdfDataForWebID(rdfData, webId, MembershipRole);
  return solidPodPolicies
}

async function parseworkflowWebID(rdfData, webId) {
  const store = new N3.Store();
  const parser = new N3.Parser();
  let workflowData = [];

  try {
    const parsedRdf = parser.parse(rdfData);
    store.addQuads(parsedRdf);
  } catch (err) {
    console.error('Error parsing RDF data:', err);
    return;
  }

  // Query the store for the workflow instance
  const memberships = store.getQuads(webId, namedNode('http://www.w3.org/ns/org#hasMembership'), null, null);

  memberships.forEach((membership) => {
    // Retrieve the role associated with the membership
    const roles = store.getObjects(membership.object, namedNode('http://www.w3.org/ns/org#role'));
    const role = roles.length > 0 ? roles[0].value : null; // Assume there is only one role per membership

    // Retrieve the workflow instance associated with the membership
    const workflowInstances = store.getObjects(membership.object, namedNode('https://solid.ti.rw.fau.de/public/ns/frog#hasWorkflowInstance'));

    workflowInstances.forEach((instance) => {
      // Collect workflow instance URI and associated role
      workflowData.push({ workflowInstance: instance.value, MembershipRole: role });
      // console.log("Workflow Instance:", instance.value, "Role:", role);
    });
  });
  return workflowData;
}

// async function parseRdfDataForWebID(rdfData, webId, MembershipRole) {
//   const store = new N3.Store();
//   const parser = new N3.Parser();
//
//   try {
//     const parsedRdf = parser.parse(rdfData);
//     store.addQuads(parsedRdf);
//   } catch (err) {
//     console.error('Error parsing RDF data:', err);
//     return;
//   }
//
//   const accessPolicies = {};
//   const rolesHeld = new Set(); // Use a Set to store unique roles held by the webId
//
//   // Append the provided MembershipRole if it is not already in the roles array
//   if (MembershipRole.size > 0) {
//     MembershipRole.forEach((role) => {
//       const posts = store.getSubjects(
//           namedNode('http://www.w3.org/ns/org#role'),
//           namedNode(role)
//       );
//       for (const post of posts) {
//         console.log("post: ", post)
//         const subject = post;
//         const predicate = namedNode('http://www.w3.org/ns/org#heldBy');
//         const object = namedNode(webId);
//
//         // Create the quad
//         const newQuad = quad(subject, predicate, object);
//         console.log(newQuad)
//         store.addQuad(newQuad);
//       }
//     });
//   }
//
//   // Iterate over all subjects (posts) where 'heldBy' predicate matches the webId
//   const posts = store.getSubjects(
//     namedNode('http://www.w3.org/ns/org#heldBy'),
//     namedNode(webId)
//   );
//   for (const post of posts) {
//     const roles = store.getObjects(
//       post,
//       namedNode('http://www.w3.org/ns/org#role')
//     );
//     for (const role of roles) {
//       rolesHeld.add(role.value); // Collect the role URI
//       const accessQuads = store.getObjects(
//         role,
//         namedNode('https://solid.ti.rw.fau.de/public/ns/frog#access')
//       );
//
//       for (const accessQuad of accessQuads) {
//         const methodNodes = store.getObjects(
//           accessQuad,
//           namedNode('https://solid.ti.rw.fau.de/public/ns/frog#httpMethod')
//         );
//
//         const uriNodes = store.getObjects(
//           accessQuad,
//           namedNode('https://solid.ti.rw.fau.de/public/ns/frog#uri')
//         );
//
//         // Ensure there are multiple methods and URIs
//         for (const methodNode of methodNodes) {
//           for (const uriNode of uriNodes) {
//             // Ensure method and URI nodes are valid
//             if (methodNode && uriNode) {
//               const method = methodNode.value;
//               const uri = uriNode.value;
//
//               if (!accessPolicies[webId]) {
//                 accessPolicies[webId] = {};
//               }
//               if (!accessPolicies[webId][method]) {
//                 accessPolicies[webId][method] = [];
//               }
//
//               accessPolicies[webId][method].push(uri);
//             }
//           }
//         }
//       }
//     }
//   }
//
//   console.log("Roles held by ", webId, "are :", rolesHeld)
//
//   return accessPolicies, rolesHeld;
// }

async function parseRdfDataForWebID(rdfData, webId, MembershipRole) {
  const store = new N3.Store();
  const parser = new N3.Parser();

  try {
    const parsedRdf = parser.parse(rdfData);
    store.addQuads(parsedRdf);
  } catch (err) {
    console.error('Error parsing RDF data:', err);
    return {};
  }

  const accessPolicies = {};
  const rolesHeld = new Set();

  // Append MembershipRole to store if it is not already present
  addMembershipRolesToStore(store, MembershipRole, webId);

  // Find posts held by the webId
  const posts = store.getSubjects(
    namedNode('http://www.w3.org/ns/org#heldBy'),
    namedNode(webId)
  );

  for (const post of posts) {
    const roles = store.getObjects(post, namedNode('http://www.w3.org/ns/org#role'));
    for (const role of roles) {
      rolesHeld.add(role.value); // Collect unique role URIs

      // Retrieve and process access policies
      const accessQuads = store.getObjects(
        role,
        namedNode('https://solid.ti.rw.fau.de/public/ns/frog#access')
      );

      for (const accessQuad of accessQuads) {
        processAccessQuad(store, accessQuad, webId, accessPolicies);
      }
    }
  }

  console.log("Roles held by", webId, "are:", rolesHeld);

  return accessPolicies;
}

// Helper function to add MembershipRoles to the store
function addMembershipRolesToStore(store, MembershipRole, webId) {
  if (MembershipRole.size > 0) {
    for (const role of MembershipRole) {
      const posts = store.getSubjects(
        namedNode('http://www.w3.org/ns/org#role'),
        namedNode(role)
      );
      for (const post of posts) {
        const subject = post;
        const predicate = namedNode('http://www.w3.org/ns/org#heldBy');
        const object = namedNode(webId);
        const newQuad = quad(subject, predicate, object);

        store.addQuad(newQuad);

      }
    }
  }
}

// Helper function to process access quads
function processAccessQuad(store, accessQuad, webId, accessPolicies) {
  const methodNodes = store.getObjects(
    accessQuad,
    namedNode('https://solid.ti.rw.fau.de/public/ns/frog#httpMethod')
  );

  const uriNodes = store.getObjects(
    accessQuad,
    namedNode('https://solid.ti.rw.fau.de/public/ns/frog#uri')
  );

  for (const methodNode of methodNodes) {
    for (const uriNode of uriNodes) {
      if (methodNode && uriNode) {
        const method = methodNode.value;
        const uri = uriNode.value;

        if (!accessPolicies[webId]) {
          accessPolicies[webId] = {};
        }
        if (!accessPolicies[webId][method]) {
          accessPolicies[webId][method] = [];
        }

        accessPolicies[webId][method].push(uri);
      }
    }
  }
}


// Middleware for forwarding the PUT request to the Solid Pod authenticated as SME

// Set up middleware
app.use(express.text());
app.use(authenticateSME);

app.all('/offer/1', async (req, res, next) => {
  const path = req.originalUrl;
  console.log(req.method, "route from Postman:", path);

  // const webId = 'https://tom.solid.aifb.kit.edu/profile/card#me';
  const webId = 'https://max.solid.aifb.kit.edu/profile/card#me';
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


