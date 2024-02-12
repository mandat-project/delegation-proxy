const crypto = require('crypto');

function calculateJWKThumbprint(jwk) {
  const sortedJWK = {};
  Object.keys(jwk).sort().forEach((key) => {
    sortedJWK[key] = jwk[key];
  });

  // Convert the sorted JWK to JSON
  const jwkString = JSON.stringify(sortedJWK);

  // Calculate SHA-256 hash
  const hash = crypto.createHash('sha256').update(Buffer.from(jwkString)).digest();

  // Encode the hash in base64url format
  return base64urlEncode(hash);
}

// Function to encode in base64url format
function base64urlEncode(input) {
  return Buffer.from(input).toString('base64url');
}

module.exports = { calculateJWKThumbprint };
