const {split, combine} = require('../');

describe('shamir-secret-sharing', () => {
  const secret = new Uint8Array([0x73, 0x65, 0x63, 0x72, 0x65, 0x74]);

  it('cannot split with invalid arguments', async () => {
    const secretWrongType = split([0x73, 0x65, 0x63, 0x72, 0x65, 0x74], 3, 2);
    await expect(secretWrongType).rejects.toThrow(new TypeError('secret must be a Uint8Array'));

    const emptySecret = split(new Uint8Array(0), 3, 2);
    await expect(emptySecret).rejects.toThrow(new Error('secret cannot be empty'));

    const sharesWrongType = split(secret, '3', 2);
    await expect(sharesWrongType).rejects.toThrow(new TypeError('shares must be a number'));

    const sharesLT2 = split(secret, 1, 2);
    await expect(sharesLT2).rejects.toThrow(
      new RangeError('shares must be at least 2 and at most 255'),
    );

    const sharesGT255 = split(secret, 256, 2);
    await expect(sharesGT255).rejects.toThrow(
      new RangeError('shares must be at least 2 and at most 255'),
    );

    const thresholdWrongType = split(secret, 3, '2');
    await expect(thresholdWrongType).rejects.toThrow(new TypeError('threshold must be a number'));

    const thresholdLT2 = split(secret, 2, 1);
    await expect(thresholdLT2).rejects.toThrow(
      new RangeError('threshold must be at least 2 and at most 255'),
    );

    const thresholdGT255 = split(secret, 2, 256);
    await expect(thresholdGT255).rejects.toThrow(
      new RangeError('threshold must be at least 2 and at most 255'),
    );

    const thresholdGTShares = split(secret, 3, 4);
    await expect(thresholdGTShares).rejects.toThrow(
      new Error('shares cannot be less than threshold'),
    );
  });

  it('cannot combine with invalid arguments', async () => {
    const bogusShare1 = new Uint8Array([0xff, 0x23]);
    const bogusShare2 = new Uint8Array([0xc1, 0xa7, 0x04]);

    const sharesWrongType = combine(bogusShare1, bogusShare2);
    await expect(sharesWrongType).rejects.toThrow(new TypeError('shares must be an Array'));

    const sharesWrongMinLength = combine([bogusShare1]);
    await expect(sharesWrongMinLength).rejects.toThrow(
      new TypeError('shares must have at least 2 and at most 255 elements'),
    );

    const sharesWrongMaxLength = combine(new Array(256).fill(new Uint8Array(2)));
    await expect(sharesWrongMaxLength).rejects.toThrow(
      new TypeError('shares must have at least 2 and at most 255 elements'),
    );

    const shareWrongType = combine([bogusShare1, 'bogusShare2']);
    await expect(shareWrongType).rejects.toThrow(new TypeError('each share must be a Uint8Array'));

    const shareWrongMinLength = combine([new Uint8Array(0), bogusShare2]);
    await expect(shareWrongMinLength).rejects.toThrow(
      new TypeError('each share must be at least 2 bytes'),
    );

    const shareLengthMismatch = combine([bogusShare1, bogusShare2]);
    await expect(shareLengthMismatch).rejects.toThrow(
      new TypeError('all shares must have the same byte length'),
    );

    const shareDuplicates = combine([bogusShare2, bogusShare2]);
    await expect(shareDuplicates).rejects.toThrow(
      new TypeError('shares must contain unique values but a duplicate was found'),
    );
  });

  it('can split a secret into multiple shares', async () => {
    const shares = await split(secret, 3, 2);
    expect(shares.length).toBe(3);

    const [a, b, c] = shares;
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.byteLength).toBe(secret.byteLength + 1);
    expect(b).toBeInstanceOf(Uint8Array);
    expect(b.byteLength).toBe(secret.byteLength + 1);
    expect(c).toBeInstanceOf(Uint8Array);
    expect(c.byteLength).toBe(secret.byteLength + 1);

    const reconstructed = await combine([a, c]);
    expect(reconstructed).toEqual(secret);
  });

  it('can split a 1 byte secret', async () => {
    const oneByteSecret = new Uint8Array([0x33]);

    const shares = await split(oneByteSecret, 3, 2);
    expect(shares.length).toBe(3);

    const [a, b, c] = shares;
    expect(a.byteLength).toBe(2);
    expect(b.byteLength).toBe(2);
    expect(c.byteLength).toBe(2);

    const reconstructed = await combine([a, b]);
    expect(reconstructed).toEqual(oneByteSecret);
  });

  it('can require all shares to reconstruct', async () => {
    const shares = await split(secret, 2, 2);
    expect(shares.length).toBe(2);
    await expect(combine(shares)).resolves.toEqual(secret);
  });

  it('can combine using any combination of shares that meets the given threshold', async () => {
    const shares = await split(secret, 5, 3);
    expect(shares.length).toBe(5);

    // Test combining all permutations of 3 shares
    for (let i = 0; i < 5; i++) {
      expect(shares[i]).toBeInstanceOf(Uint8Array);
      expect(shares[i].byteLength).toBe(secret.byteLength + 1);
      for (let j = 0; j < 5; j++) {
        if (j === i) {
          continue;
        }
        for (let k = 0; k < 5; k++) {
          if (k === i || k === j) {
            continue;
          }
          const reconstructed = combine([shares[i], shares[j], shares[k]]);
          await expect(reconstructed).resolves.toEqual(secret);
        }
      }
    }
  });
});
