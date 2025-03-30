import * as jose from "jose";

class RSAKeyService {
  private static instance: RSAKeyService;
  private privateKey: CryptoKey | null = null;
  private publicKey: string | null = null;
  private initialized: boolean = false;
  private algorithm: RsaHashedKeyGenParams;

  private constructor(algorithm: RsaHashedKeyGenParams) {
    this.algorithm = algorithm;
  }

  public static async getInstance(
    algorithm: RsaHashedKeyGenParams = {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
  ): Promise<RSAKeyService> {
    if (!RSAKeyService.instance) {
      RSAKeyService.instance = new RSAKeyService(algorithm);
      await RSAKeyService.instance.generateKeys();
    }
    return RSAKeyService.instance;
  }

  private async generateKeys() {
    if (this.initialized) return;
    const keyPair = await crypto.subtle.generateKey(this.algorithm, true, [
      "encrypt",
      "decrypt",
    ]);

    this.privateKey = keyPair.privateKey;

    const exportedPublicKey = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey,
    );
    this.publicKey = btoa(
      String.fromCharCode(...new Uint8Array(exportedPublicKey)),
    );

    this.initialized = true;
  }

  public getPublicKey(): string | null {
    return this.publicKey;
  }

  public async encryptWithServerPublicKey(
    data: string,
    jwkPublicKey: JsonWebKey,
    alg: string = "RSA-OAEP-256",
    enc: string = "A256GCM",
  ): Promise<string> {
    try {
      const encodedData = new TextEncoder().encode(data);
      const publicKey = await jose.importJWK(jwkPublicKey, alg);

      return await new jose.CompactEncrypt(encodedData)
        .setProtectedHeader({ alg, enc })
        .encrypt(publicKey);
    } catch (error) {
      throw error;
    }
  }

  public async decryptWithPrivateKey(encryptedData: string): Promise<string> {
    try {
      if (!this.privateKey) throw new Error("Private key is not available!");

      const pkcs8 = await crypto.subtle.exportKey("pkcs8", this.privateKey);
      const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(
        pkcs8,
      ).toString("base64")}\n-----END PRIVATE KEY-----`;

      const josePrivateKey = await jose.importPKCS8(pkcs8Pem, "RSA-OAEP");

      const { plaintext } = await jose.compactDecrypt(
        encryptedData,
        josePrivateKey,
      );

      return new TextDecoder().decode(plaintext);
    } catch (error) {
      throw new Error(`Decryption failed: ${error}`);
    }
  }
}

export default async (algorithm?: RsaHashedKeyGenParams) =>
  await RSAKeyService.getInstance(algorithm);
