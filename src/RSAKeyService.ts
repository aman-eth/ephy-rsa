import * as jose from "jose";

class RSAKeyService {
  private static instance: RSAKeyService;
  private privateKey: CryptoKey | null = null;
  private publicKey: string | null = null;
  private initialized: boolean = false;
  private algorithm: RsaHashedKeyGenParams = {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  };

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
    jwkPublicKey: JsonWebKey | string, // Accepts both JWK and PEM/Base64
    alg:
      | "RSA-OAEP"
      | "RSA-OAEP-256"
      | "RSA-OAEP-384"
      | "RSA-OAEP-512" = "RSA-OAEP-256",
    enc: "A128GCM" | "A192GCM" | "A256GCM" = "A256GCM",
  ): Promise<string> {
    try {
      const encodedData = new TextEncoder().encode(data);

      let publicKey: any;

      if (typeof jwkPublicKey === "string") {
        // Assume PEM or Base64 format
        const pemPublicKey = `-----BEGIN PUBLIC KEY-----\n${jwkPublicKey}\n-----END PUBLIC KEY-----`;
        publicKey = await jose.importSPKI(pemPublicKey, alg);
      } else {
        publicKey = await jose.importJWK({ ...jwkPublicKey } as jose.JWK, alg);
      }

      return await new jose.CompactEncrypt(encodedData)
        .setProtectedHeader({ alg, enc })
        .encrypt(publicKey);
    } catch (error) {
      throw new Error(`Encryption failed: ${error}`);
    }
  }

  public async decryptWithPrivateKey(encryptedData: string): Promise<string> {
    try {
      if (!this.privateKey) throw new Error("Private key is not available!");

      const pkcs8 = await crypto.subtle.exportKey("pkcs8", this.privateKey);

      // Replace Buffer usage with browser-compatible base64 conversion
      const base64Key = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
      const pkcs8Pem = `-----BEGIN PRIVATE KEY-----\n${base64Key}\n-----END PRIVATE KEY-----`;

      const josePrivateKey = await jose.importPKCS8(
        pkcs8Pem,
        this.algorithm.name,
      );

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
