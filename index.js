const {
  ID,
  SECRET,
  OIDC_USER,
  POD_URL,
  ORGANIZATION_RESOURCE,
  WORKFLOW_TTL,
  MEMBERSHIPS_RESOURCE,
  ACTIVITIES_TTL,
  SIGNATURE_TTL
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
    // Dynamically import the 'node-fetch' module to use fetch for making HTTP requests
    const { default: fetch } = await import('node-fetch');

    // Assign the base Solid Pod URL (replace POD_URL with actual variable or constant)
    const podUrl = POD_URL;

    // Capture the HTTP method (GET, POST, PUT, etc.) from the incoming request
    const method = req.method;

    // Define the request options including the method and headers
    const requestOptions = {
      method: method,
      headers: {'content-type': req.headers['content-type']}, // Pass along the content type from the original request
    };

    // If the request method is PUT or POST, include the request body in the options
    if (method === 'PUT' || method === 'POST') {
      requestOptions.body = req.body;
    }

    // Use the session from req.smeSession to fetch from the Solid Pod, combining the base pod URL with the provided path
    const pod_response = await req.smeSession.fetch(`${podUrl}${url}`, requestOptions);

    // If the request is a GET method, we expect a text response and assign it to req.podResponse
    if (method === 'GET') {
      req.podResponse = await pod_response.text();
    }
    // For non-GET requests, assign the entire response object to req.podResponse
    else {
      req.podResponse = await pod_response;
    }

    // Call the next middleware function in the stack to continue processing the request
    next();
  } catch (error) {
    // Handle any errors that occur during the request to the Solid Pod
    console.error(`Error forwarding ${method} request to Solid Pod as SME: ${error.message}`);
    console.error('Response from Solid Pod:', error.response);

    // Send a 500 Internal Server Error response to the client if something goes wrong
    res.status(500).send(`Error forwarding ${method} request to Solid Pod as SME`);
  }
};


async function hasAccess(req, res, webId, uri, method) {
  // Log the URI for which access needs to be checked
  console.log("URI to check access", uri);

  // Fetch various resources from the Solid Pod that are needed for access control
  const organizationResource = await fetchSolidPodInfo(req, res, ORGANIZATION_RESOURCE);
  const solidPodActivity = await fetchSolidPodInfo(req, res, ACTIVITIES_TTL);
  const solidPodWorkflow = await fetchSolidPodInfo(req, res, WORKFLOW_TTL);
  const membershipResource = await fetchSolidPodInfo(req, res, MEMBERSHIPS_RESOURCE);
  const solidPodSignature = await fetchSolidPodInfo(req, res, SIGNATURE_TTL);

  // Store the fetched Turtle data into an array
  const turtleDataArray = [
    organizationResource,
    solidPodActivity,
    solidPodWorkflow,
    membershipResource,
    solidPodSignature
  ];

  // Merge the Turtle data from different resources into a single Turtle string
  const mergedTurtleString = await mergeTurtleData(turtleDataArray);

  // Define the path to the rules file for workflow instances and read its contents
  const workflowInstancesRulesPath = path.join(__dirname, '/rules/workflow_rules.n3');
  const activitiesInstancesRules = fs.readFileSync(workflowInstancesRulesPath, 'utf-8');

  // Combine the merged Turtle data with the rules to form the complete data string for reasoning
  const activities_datastring = `${mergedTurtleString}\n${activitiesInstancesRules}`;

  // Perform reasoning on the data string to generate inferences
  const finalDataString = await n3reasoner(activities_datastring);

  // Parse the workflow approvals status from the reasoning result
  const workflowApprovals = await parseApprovalStatus(finalDataString);
  console.log("Approvals: ", workflowApprovals);

  // Fetch workflow data based on the user's WebID and membership information
  const workflowData = await fetchWorkflowData(req, res, webId, membershipResource);

  // Initialize a set to store the user's membership roles from approved workflows
  const MembershipRoles = new Set();

  // Iterate through the workflow data and check if the workflow instance is approved
  for (const workflow of workflowData) {
    if (workflowApprovals[workflow['workflowInstance']] === 'approved') {
      // If the workflow instance is approved, add the associated MembershipRole to the set
      if (workflowApprovals[workflow['workflowInstance']]) {
        MembershipRoles.add(workflow['MembershipRole']);
      } else {
        // Log if a workflow instance is not found in the approved workflows
        console.log("workflowInstance is not present in the Approved workflows");
      }
    }
  }

  // Check the Solid Pod access policy based on the user's WebID, URI, method, and membership roles
  const policies = await checkSolidPodAccess(req, res, webId, uri, method, MembershipRoles);
  console.log("URL policy: ", policies);

  // Return the access policies for the requested URI
  return policies;
}

async function parseApprovalStatus(rdfData) {
  // Initialize an N3 store and parser to handle RDF data
  const store = new N3.Store();
  const parser = new N3.Parser();
  const approvalStatusDict = {};  // Dictionary to store approval status for each subject

  try {
    // Parse the RDF data and add the parsed triples (quads) to the store
    const parsedRdf = parser.parse(rdfData);
    store.addQuads(parsedRdf);
  } catch (err) {
    // Log any errors encountered during RDF parsing and return an empty object
    console.error('Error parsing RDF data:', err);
    return {};
  }

  // Define the URI for the frog:approval predicate
  const approvalPredicate = namedNode('https://solid.ti.rw.fau.de/public/ns/frog#approval');

  // Define nodes representing "approved" and "not approved" statuses
  const approvedNode = namedNode('https://solid.ti.rw.fau.de/public/ns/frog#approved');
  const notApprovedNode = namedNode('https://solid.ti.rw.fau.de/public/ns/frog#notApproved');

  // Get all unique subjects that have the frog:approval predicate
  const subjects = [...new Set(store.getQuads(null, approvalPredicate, null, null).map(quad => quad.subject.value))];

  // Iterate over each subject and check its approval status
  subjects.forEach(subject => {
    // Retrieve all quads (triples) where the subject has an approval status
    const approvalQuads = store.getQuads(namedNode(subject), approvalPredicate, null, null);

    // If no approval quads are found, set the status as 'open'
    if (approvalQuads.length === 0) {
      approvalStatusDict[subject] = 'open';
    } else {
      // Otherwise, check the object of the approval quad to determine status
      const approvalQuad = approvalQuads[0];
      if (approvalQuad.object.equals(approvedNode)) {
        approvalStatusDict[subject] = 'approved';  // Set status to 'approved' if it matches
      } else if (approvalQuad.object.equals(notApprovedNode)) {
        approvalStatusDict[subject] = 'not approved';  // Set status to 'not approved' if it matches
      }
    }
  });

  // Return the dictionary containing subjects and their approval statuses
  return approvalStatusDict;
}


async function fetchWorkflowData(req, res, webId, membershipContainer) {
  // Extract workflows for the given WebID by calling the parseworkflowWebID function
  // The function parses the membershipContainer (which holds membership information)
  // and retrieves the workflows associated with the specified WebID (user).
  const workflows = parseworkflowWebID(membershipContainer, webId);

  // Return the extracted workflows to the caller.
  return workflows;
}

async function fetchSolidPodInfo(req, res, url) {
  // Fetch the resource from the provided URL using the session from req.smeSession
  const sme_response = await req.smeSession.fetch(url);
  const rdfData = await sme_response.text();  // Get the RDF data as text from the response

  // Initialize an N3 parser and store to parse and store the RDF data
  const parser = new N3.Parser();
  const store = new N3.Store();
  store.addQuads(parser.parse(rdfData));  // Parse the RDF data and add it to the store

  // Find all resources that are contained within the current resource using ldp:contains
  const ldpContains = store.getQuads(null, namedNode('http://www.w3.org/ns/ldp#contains'), null, null);

  // Check if there are any ldp:contains triples (indicating the resource is a container)
  if (ldpContains.length > 0) {
    // If the resource is a container, initialize an array to hold Turtle file data
    const turtleFiles = [];

    // Iterate over the contained resources (found through ldp:contains triples)
    for (const quad of ldpContains) {
      const fileUrl = quad.object.value;  // Get the URL of the contained resource
      if (fileUrl.endsWith('.ttl')) {  // Check if the resource is a Turtle (.ttl) file (this check could be relaxed as per the comment)
        // Construct the full URL of the Turtle file (if relative) and fetch its content
        const updatedFileUrl = url + fileUrl;
        const fileResponse = await req.smeSession.fetch(updatedFileUrl);
        const fileData = await fileResponse.text();  // Get the Turtle file content
        turtleFiles.push(fileData);  // Add the Turtle data to the array
      }
    }

    // Merge all fetched Turtle data into one combined Turtle string and return it
    return await mergeTurtleData(turtleFiles);
  } else {
    // If no ldp:contains triples are found, it's a single Turtle file, so return the RDF data directly
    return rdfData;
  }
}

async function checkSolidPodAccess(req, res, webId, uri, method, MembershipRole) {
  // Fetch the access policies from the Solid Pod for the given webId and MembershipRole
  const solidPodPolicies = await fetchSolidPodPolicies(req, res, webId, MembershipRole);
  console.log("solidPodPolicies ", solidPodPolicies);

  // Retrieve the access policies for the specified webId
  const policies = solidPodPolicies[webId];

  // Check if policies exist for this webId and if the HTTP method (GET, POST, etc.)
  // is allowed for the specific URI (resource) based on the policies
  if (policies && (policies[method].includes(uri))) {
    return true; // Access is granted if the method for the given URI is allowed
  }
  return false; // Access denied if no matching policy is found for the method and URI
}


async function fetchSolidPodPolicies(req, res, webId, MembershipRole) {
  // Define the endpoint URL to fetch policies related to the Solid Pod (e.g., for finance data)
  const podEndpoint = POD_FINANCE_URL;

  // Fetch the RDF data from the Solid Pod using the session from req.smeSession
  const sme_response = await req.smeSession.fetch(`${podEndpoint}`);
  const rdfData = await sme_response.text();  // Extract the RDF data as a text string

  // Parse the RDF data to extract policies that apply to the specified webId and MembershipRole
  const solidPodPolicies = parseRdfDataForWebID(rdfData, webId, MembershipRole);

  // Return the parsed policies
  return solidPodPolicies;
}

async function parseworkflowWebID(rdfData, webId) {
  const store = new N3.Store();  // Create an N3 store to hold the RDF data
  const parser = new N3.Parser();  // Create an N3 parser to parse RDF data
  let workflowData = [];  // Initialize an empty array to hold workflow data

  try {
    // Parse the RDF data and add the parsed quads to the store
    const parsedRdf = parser.parse(rdfData);
    store.addQuads(parsedRdf);
  } catch (err) {
    // Log any errors encountered during RDF parsing
    console.error('Error parsing RDF data:', err);
    return;
  }

  // Query the store to find all memberships for the given WebID
  // This searches for quads where webId has a membership (org#hasMembership)
  const memberships = store.getQuads(webId, namedNode('http://www.w3.org/ns/org#hasMembership'), null, null);

  // Iterate over each membership found
  memberships.forEach((membership) => {
    // Retrieve the role associated with this membership
    const roles = store.getObjects(membership.object, namedNode('http://www.w3.org/ns/org#role'));
    const role = roles.length > 0 ? roles[0].value : null;  // Assume only one role per membership

    // Retrieve the workflow instance associated with this membership
    const workflowInstances = store.getObjects(membership.object, namedNode('https://solid.ti.rw.fau.de/public/ns/frog#hasWorkflowInstance'));

    // Iterate over each workflow instance and collect its URI and associated role
    workflowInstances.forEach((instance) => {
      workflowData.push({ workflowInstance: instance.value, MembershipRole: role });  // Store instance and role
      // Uncomment the line below for debugging output
      // console.log("Workflow Instance:", instance.value, "Role:", role);
    });
  });

  // Return the collected workflow data
  return workflowData;
}

async function parseRdfDataForWebID(rdfData, webId, MembershipRole) {
  const store = new N3.Store();  // Create an N3 store to hold the parsed RDF data
  const parser = new N3.Parser();  // Create an N3 parser to parse RDF data

  try {
    // Parse the RDF data and add the parsed triples (quads) to the store
    const parsedRdf = parser.parse(rdfData);
    store.addQuads(parsedRdf);
  } catch (err) {
    // Log any errors during RDF parsing
    console.error('Error parsing RDF data:', err);
    return {};  // Return an empty object in case of parsing errors
  }

  const accessPolicies = {};  // Object to store access policies related to the WebID
  const rolesHeld = new Set();  // Set to keep track of unique roles held by the WebID

  // Append the MembershipRole to the RDF store if it is not already present
  addMembershipRolesToStore(store, MembershipRole, webId);

  // Find all posts held by the WebID (i.e., positions or memberships) using the 'org#heldBy' predicate
  const posts = store.getSubjects(
    namedNode('http://www.w3.org/ns/org#heldBy'),
    namedNode(webId)
  );

  // Iterate over each post found
  for (const post of posts) {
    // Retrieve the roles associated with this post using the 'org#role' predicate
    const roles = store.getObjects(post, namedNode('http://www.w3.org/ns/org#role'));

    for (const role of roles) {
      // Add the role URI to the set of roles held by the WebID
      rolesHeld.add(role.value);  // Ensure only unique roles are added

      // Retrieve the access policies associated with the role using the 'frog#access' predicate
      const accessQuads = store.getObjects(
        role,
        namedNode('https://solid.ti.rw.fau.de/public/ns/frog#access')
      );

      // Process each access quad (access policy) and store it in the accessPolicies object
      for (const accessQuad of accessQuads) {
        processAccessQuad(store, accessQuad, webId, accessPolicies);
      }
    }
  }
  // Log the roles held by the WebID for debugging purposes
  console.log("Roles held by", webId, "are:", rolesHeld);

  // Return the constructed access policies for the WebID
  return accessPolicies;
}


// Helper function to add MembershipRoles to the store
function addMembershipRolesToStore(store, MembershipRole, webId) {
  // Check if the MembershipRole set is not empty
  if (MembershipRole.size > 0) {
    // Iterate over each role in the MembershipRole set
    for (const role of MembershipRole) {
      // Find all posts (positions or memberships) associated with this role
      const posts = store.getSubjects(
        namedNode('http://www.w3.org/ns/org#role'),
        namedNode(role)
      );

      // Iterate over each post found for this role
      for (const post of posts) {
        // Define the RDF triple to add: (post, org#heldBy, webId)
        const subject = post;  // The post (membership) associated with the role
        const predicate = namedNode('http://www.w3.org/ns/org#heldBy');  // Predicate indicating the role is held by webId
        const object = namedNode(webId);  // The WebID for which the role is held

        // Create a new RDF quad with the subject, predicate, and object
        const newQuad = quad(subject, predicate, object);

        // Add the new quad to the RDF store
        store.addQuad(newQuad);
      }
    }
  }
}

// Helper function to process access quads
function processAccessQuad(store, accessQuad, webId, accessPolicies) {
  // Retrieve all HTTP methods associated with the accessQuad
  const methodNodes = store.getObjects(
    accessQuad,
    namedNode('https://solid.ti.rw.fau.de/public/ns/frog#httpMethod')
  );

  // Retrieve all URIs associated with the accessQuad
  const uriNodes = store.getObjects(
    accessQuad,
    namedNode('https://solid.ti.rw.fau.de/public/ns/frog#uri')
  );

  // Iterate over each HTTP method retrieved
  for (const methodNode of methodNodes) {
    // Iterate over each URI retrieved
    for (const uriNode of uriNodes) {
      // Ensure both methodNode and uriNode are valid
      if (methodNode && uriNode) {
        const method = methodNode.value;  // Extract the HTTP method (e.g., GET, POST)
        const uri = uriNode.value;        // Extract the URI (resource) the method applies to

        // Initialize the accessPolicies object for the webId if it does not exist
        if (!accessPolicies[webId]) {
          accessPolicies[webId] = {};
        }
        // Initialize the method property for the webId if it does not exist
        if (!accessPolicies[webId][method]) {
          accessPolicies[webId][method] = [];
        }

        // Add the URI to the list of allowed URIs for the specified method under the webId
        accessPolicies[webId][method].push(uri);
      }
    }
  }
}

// Set up middleware
app.use(express.text());
app.use(authenticateSME);

app.all('/offer/1', async (req, res, next) => {
  // Capture the full path of the incoming request
  const path = req.originalUrl;
  console.log(req.method, "route from Postman:", path);

  // Define the WebID and URI to be used for access checks
  const webId = 'https://max.solid.aifb.kit.edu/profile/card#me'; // Current WebID
  const uri = 'https://bank.solid.aifb.kit.edu/offer/1'; // URI of the resource being accessed

  // Check if the request has access permissions for the specified WebID, URI, and HTTP method
  const accessGranted = await hasAccess(req, res, webId, uri, req.method);
  console.log('Access Granted:', accessGranted);

  // If access is granted, process the request further
  if (accessGranted) {
    // Extract the authorization token and DPoP proof from request headers
    const accessToken = req.headers['authorization'].replace('DPoP ', ''); // Remove 'DPoP ' prefix
    const dpopProofFromRequest = req.headers['dpop'];

    // Decode the DPoP proof and access token to verify their contents
    const decodedDPoPProof = jwt.decode(dpopProofFromRequest, { complete: true });
    const decodedAccessToken = jwt.decode(accessToken, { complete: true });

    // Calculate the thumbprint of the JWK from the DPoP proof
    const thumbprint = calculateJWKThumbprint(decodedDPoPProof.header.jwk);

    // Verify if the token's 'jkt' claim matches the thumbprint of the JWK
    if (decodedAccessToken.payload.cnf.jkt === thumbprint) {
      // If the token is valid, forward the request to the Solid Pod
      await forwardRequestToPodAsSME(req, res, next, path);
    } else {
      // If the token is invalid, respond with a 401 Unauthorized status
      res.status(401).json({ message: 'Invalid client for this access token' });
    }
  } else {
    // If access is not granted, respond with a 403 Forbidden status
    res.status(403).json({ message: 'Access forbidden' });
  }

}, (req, res) => {
  // Send the response received from the Solid Pod back to the client
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