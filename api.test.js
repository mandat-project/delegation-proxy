const baseUrl = 'http://localhost:3000';

describe('API Tests', () => {
  it('should make a GET request', async () => {
      const { expect } = await import('chai');
      const fetch = (await import('node-fetch')).default;
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
