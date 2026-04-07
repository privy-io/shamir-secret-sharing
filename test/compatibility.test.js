const {split, combine} = require('../');

describe('shamir-secret-sharing compatibility', () => {
  // Test data
  const testSecret = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
  
  // Keep reference to original crypto
  const originalCrypto = global.crypto;
  const mockBrowserCrypto = {
    getRandomValues: function(array) {
      // Simple deterministic random generator for testing
      for (let i = 0; i < array.length; i++) {
        array[i] = (i * 41 + 7) % 256;
      }
      return array;
    }
  };

  // Generate a consistent set of shares once to use for all tests
  let testShares;

  beforeAll(async () => {
    // Generate shares in a clean environment
    global.crypto = undefined; // Use Node.js crypto
    testShares = await split(testSecret, 5, 2);
  });

  afterAll(() => {
    // Restore original global objects
    global.crypto = originalCrypto;
  });

  describe('cross-environment compatibility', () => {
    test('combining shares works in Node.js environment', async () => {
      // Use Node.js crypto
      global.crypto = undefined;
      
      // Take a subset of shares and combine them in Node.js
      const reconstructed = await combine([testShares[0], testShares[1]]);
      
      // Verify reconstruction works
      expect(reconstructed).toEqual(testSecret);
    });

    test('combining shares works in browser environment', async () => {
      // Set browser environment
      global.crypto = mockBrowserCrypto;
      
      // Take a subset of shares and combine them in browser
      const reconstructed = await combine([testShares[0], testShares[2]]);
      
      // Verify reconstruction works
      expect(reconstructed).toEqual(testSecret);
    });

    test('shares can be combined with different share subsets', async () => {
      // Test with various combinations of shares
      for (let i = 0; i < 4; i++) {
        for (let j = i + 1; j < 5; j++) {
          // Alternate between Node.js and browser environment
          global.crypto = (i % 2 === 0) ? undefined : mockBrowserCrypto;
          
          const reconstructed = await combine([testShares[i], testShares[j]]);
          expect(reconstructed).toEqual(testSecret);
        }
      }
    });
  });

  describe('api consistency across environments', () => {
    test('split function has same behavior in both environments', async () => {
      // Test in Node.js
      global.crypto = undefined;
      const nodeShares = await split(testSecret, 3, 2);
      expect(nodeShares).toHaveLength(3);
      const nodeReconstructed = await combine([nodeShares[0], nodeShares[1]]);
      expect(nodeReconstructed).toEqual(testSecret);
      
      // Test in browser
      global.crypto = mockBrowserCrypto;
      const browserShares = await split(testSecret, 3, 2);
      expect(browserShares).toHaveLength(3);
      const browserReconstructed = await combine([browserShares[0], browserShares[1]]);
      expect(browserReconstructed).toEqual(testSecret);
    });
    
    test('combine function has same interface in both environments', async () => {
      // Try combining in Node.js
      global.crypto = undefined;
      await expect(combine([testShares[3], testShares[4]])).resolves.toEqual(testSecret);
      
      // Try combining in browser
      global.crypto = mockBrowserCrypto;
      await expect(combine([testShares[2], testShares[4]])).resolves.toEqual(testSecret);
    });
  });
}); 