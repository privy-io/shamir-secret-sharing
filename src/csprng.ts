export function getRandomBytes(numBytes: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(numBytes));
}
