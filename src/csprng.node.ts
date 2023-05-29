import {randomBytes} from 'node:crypto';

export function getRandomBytes(numBytes: number): Uint8Array {
  return new Uint8Array(randomBytes(numBytes).buffer);
}
