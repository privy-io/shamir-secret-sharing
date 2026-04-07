const {split, combine} = require('../');

describe('shamir-secret-sharing performance', () => {
  // Helper function to create secrets of different sizes
  function createSecret(sizeInBytes) {
    const secret = new Uint8Array(sizeInBytes);
    for (let i = 0; i < sizeInBytes; i++) {
      secret[i] = i % 256;
    }
    return secret;
  }

  // Helper function to measure execution time
  async function measureTime(fn) {
    const start = performance.now();
    const result = await fn();
    const end = performance.now();
    return {
      result,
      duration: end - start
    };
  }

  // Simple console reporter helper
  const report = {
    header: (text) => console.log(`\n\x1b[1m${text}\x1b[0m`),
    line: () => console.log('─'.repeat(60)),
    row: (cols) => console.log(cols.join(' │ ')),
    time: (ms) => `${ms.toFixed(2)}ms`.padStart(10)
  };

  describe('splitting secrets', () => {
    test('performance with different secret sizes', async () => {
      const sizes = [64, 256, 1024, 4096, 16384]; // bytes
      const shares = 5;
      const threshold = 3;
      
      report.header('SPLIT OPERATION: SCALING BY SECRET SIZE');
      report.line();
      report.row(['SIZE (bytes)'.padEnd(12), 'TIME'.padEnd(10)]);
      report.line();
      
      for (const size of sizes) {
        const secret = createSecret(size);
        const {duration} = await measureTime(() => split(secret, shares, threshold));
        const sizeStr = size < 1024 ? `${size}B` : `${size/1024}KB`;
        report.row([sizeStr.padEnd(12), report.time(duration)]);
      }
    }, 30000);

    test('performance with different share counts', async () => {
      const size = 1024; // bytes
      const secret = createSecret(size);
      const shareCounts = [3, 5, 10, 20, 50, 100];
      
      report.header('SPLIT OPERATION: SCALING BY SHARE COUNT');
      report.line();
      report.row(['SHARES'.padEnd(10), 'THRESHOLD'.padEnd(10), 'TIME'.padEnd(10)]);
      report.line();
      
      for (const shareCount of shareCounts) {
        const threshold = Math.max(2, Math.floor(shareCount / 2));
        const {duration} = await measureTime(() => split(secret, shareCount, threshold));
        report.row([
          `${shareCount}`.padEnd(10), 
          `${threshold}`.padEnd(10), 
          report.time(duration)
        ]);
      }
    }, 30000);
  });

  describe('combining shares', () => {
    test('performance with different secret sizes', async () => {
      const sizes = [64, 256, 1024, 4096, 16384]; // bytes
      const shares = 5;
      const threshold = 3;
      
      report.header('COMBINE OPERATION: SCALING BY SECRET SIZE');
      report.line();
      report.row(['SIZE (bytes)'.padEnd(12), 'TIME'.padEnd(10)]);
      report.line();
      
      for (const size of sizes) {
        const secret = createSecret(size);
        const allShares = await split(secret, shares, threshold);
        const sharesToCombine = allShares.slice(0, threshold);
        
        const {duration} = await measureTime(() => combine(sharesToCombine));
        const sizeStr = size < 1024 ? `${size}B` : `${size/1024}KB`;
        report.row([sizeStr.padEnd(12), report.time(duration)]);
      }
    }, 30000);

    test('performance with different threshold counts', async () => {
      const size = 1024; // bytes
      const secret = createSecret(size);
      const shareCount = 100;
      const thresholds = [2, 5, 10, 25, 50, 100];
      
      report.header('COMBINE OPERATION: SCALING BY THRESHOLD');
      report.line();
      report.row(['THRESHOLD'.padEnd(10), 'TIME'.padEnd(10)]);
      report.line();
      
      // First generate the maximum shares we'll need
      const allShares = await split(secret, shareCount, shareCount);
      
      for (const threshold of thresholds) {
        if (threshold > shareCount) continue;
        
        const sharesToCombine = allShares.slice(0, threshold);
        const {duration} = await measureTime(() => combine(sharesToCombine));
        report.row([`${threshold}`.padEnd(10), report.time(duration)]);
      }
    }, 30000);
  });

  // A combined end-to-end test for realistic scenarios
  test('end-to-end performance with realistic parameters', async () => {
    const scenarios = [
      { name: 'Small', size: 64, shares: 3, threshold: 2 },
      { name: 'Medium', size: 1024, shares: 5, threshold: 3 },
      { name: 'Large', size: 16384, shares: 10, threshold: 6 },
    ];
    
    report.header('END-TO-END PERFORMANCE (SPLIT + COMBINE)');
    report.line();
    report.row([
      'SCENARIO'.padEnd(8), 
      'SIZE'.padEnd(8), 
      'SHARES'.padEnd(6), 
      'THRESHOLD'.padEnd(9), 
      'SPLIT'.padEnd(10), 
      'COMBINE'.padEnd(10), 
      'TOTAL'.padEnd(10)
    ]);
    report.line();
    
    for (const {name, size, shares, threshold} of scenarios) {
      const secret = createSecret(size);
      
      // Measure split
      const splitResult = await measureTime(() => split(secret, shares, threshold));
      const allShares = splitResult.result;
      const splitDuration = splitResult.duration;
      
      // Measure combine with exactly threshold shares
      const sharesToCombine = allShares.slice(0, threshold);
      const combineDuration = (await measureTime(() => combine(sharesToCombine))).duration;
      
      const totalDuration = splitDuration + combineDuration;
      const sizeStr = size < 1024 ? `${size}B` : `${size/1024}KB`;
      
      report.row([
        name.padEnd(8),
        sizeStr.padEnd(8),
        `${shares}`.padEnd(6),
        `${threshold}`.padEnd(9),
        report.time(splitDuration),
        report.time(combineDuration),
        report.time(totalDuration)
      ]);
    }
  }, 30000);
}); 