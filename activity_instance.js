const fs = require('fs').promises; // Use promises API for async/await
const path = require('path');
const n3reasoner = require('eyereasoner').n3reasoner; // Assuming you have installed eyereasoner

async function processActivityInstances() {
  try {
    // Read the contents of activity_instances.ttl
    const activityInstancesPath = path.join(__dirname, 'activity_instances_test.ttl');
    const activityInstances = await fs.readFile(activityInstancesPath, 'utf8');

    // Read the contents of n3_rules.n3
    const activitiesInstancesRulesPath = path.join(__dirname, '/rules/n3_rules.n3');
    const activitiesInstancesRules = await fs.readFile(activitiesInstancesRulesPath, 'utf8');

    // Combine the contents of both files
    const activitiesDatastring = `${activityInstances}\n${activitiesInstancesRules}`;

    // The result of the query (as a string)
    const resultString = await n3reasoner(activitiesDatastring);
    console.log(resultString);
  } catch (err) {
    console.error('Error:', err);
  }
}

// Execute the function
processActivityInstances();
