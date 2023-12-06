export declare module "shamir-secret-sharing" {
  export function split(
    secret: Buffer,
    options: { shares: number; threshold: number }
  ): Buffer[];
  export function combine(shares: Buffer[]): Buffer;
}
