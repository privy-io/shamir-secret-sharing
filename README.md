# shamir-secret-sharing

Simple zero-dependency TypeScript implementation of [Shamir's Secret Sharing algorithm](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

Implementation inspired by [hashicorp/vault](https://github.com/hashicorp/vault/tree/main/shamir).

## Usage

```typescript
import {split, combine} from 'shamir-secret-sharing';

const toUint8Array = (data: string) => new TextEncoder().encode(data);

// Example of splitting user input
const input = document.querySelector("input#secret").value.normalize('NFKC');
const secret = toUint8Array(secret);
const [share1, share2, share3] = await split(secret, 3, 2);
const reconstructed = await combine([share1, share3]);
console.log(reconstructed === secret); // true

// Example of splitting random entropy
const randomEntropy = crypto.getRandomValues(new Uint8Array(16));
const [share1, share2, share3] = await split(randomEntropy, 3, 2);
const reconstructed = await combine([share2, share3]);
console.log(reconstructed === randomEntropy); // true

// Example of splitting symmetric key
const key = await crypto.subtle.generateKey(
  {
    name: "AES-GCM",
    length: 256
  },
  true,
  ["encrypt", "decrypt"]
);
const exportedKey = await crypto.subtle.exportKey('raw', key);
const [share1, share2, share3] = await split(exportedKey, 3, 2);
const reconstructed = await combine([share2, share1]);
console.log(reconstructed === exportedKey); // true
```

## API

#### split

```ts
/**
 * Splits a `secret` into `shares` number of shares, requiring `threshold` of them to reconstruct `secret`.
 *
 * @param secret The secret value to split into shares.
 * @param shares The total number of shares to split `secret` into.
 * @param threshold The minimum number of shares required to reconstruct `secret`.
 * @returns A list of `shares` shares.
 */
declare function split(secret: Uint8Array, shares: number, threshold: number): Promise<Uint8Array[]>;
```

#### combine

```ts
/**
 * Combines `shares` to reconstruct the secret.
 *
 * @param shares The list of shares used to reconstruct the secret.
 * @returns The reconstructed secret.
 */
declare function combine(shares: Uint8Array[]): Promise<Uint8Array>;
```

## License

MIT. See LICENSE file.

Copyright 2023 Horkos, Inc.
