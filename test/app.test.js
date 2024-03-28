import { start } from 'molid';
import { expect } from 'chai';
import { fetch } from 'solid-auth-client';
import app from '../src/app.js';

const publicResource = 'http://localhost:3000/public_data';
const privateResource = 'http://localhost:3000/private_data';
const noAccessResource = 'http://localhost:3000/no_access_data';

describe('app.all(\'*\', ...);', () => {
  let molid;
  let server;

  before(async () => {
    molid = await start();
    server = app.listen(3000);
  });

  after(async () => {
    await molid.stop();
    server.close();
  });

  it('GET requests to public resources should work unauthenticated', async () => {
      try {
          const response = await fetch(`${baseUrl}/offer/1`, {
            method: 'GET',
            headers: {'Content-Type': 'application/json'},
          });
          const data = await response.text();
          console.log("GET response:", data)
          expect(response.status).to.equal(200);
      } catch (error) {
        console.error('Error during GET request:', error);
        throw error;
        }
    });

  it('should make a PUT request', async () => {
      const { expect } = await import('chai');
      const fetch = (await import('node-fetch')).default;
      const response = await fetch(`${baseUrl}/offer/1`, {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: '<http://example.org/subject> <http://example.org/predicate> "object" .'
      });
      const data = await response.text();
      console.log("PUT response:", data)
      expect(response.status).to.equal(200);
  });
});
