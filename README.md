# Ephy-RSA

Ephy-RSA is a lightweight and secure encryption library for generating **ephemeral RSA key pairs** in browser memory. It allows encrypted communication between frontend and backend without storing any keys. No plaintext data is exposed in the browser's network tab, ensuring enhanced security. This library can be used in **Next.js** and **React.js** applications seamlessly.

## tl;dr

Below is a **Sequence Diagram** illustrating the encryption and decryption process:

![Sequence Diagram](https://github.com/aman-eth/ephy-rsa/raw/main/images/sequence_diag.svg)

## Features

- 🔐 **Ephemeral RSA Key Pairs** – No keys are stored persistently.
- 🔄 **Client-Side Encryption** – Data is encrypted before leaving the browser.
- 🚀 **Easy Integration** – Works seamlessly with JSON Web Encryption (JWE) using `jose`.
- 🔒 **No Plaintext Exposure** – Data remains encrypted in transit.

## Installation

```sh
npm install ephy-rsa
```

or

```sh
yarn add ephy-rsa
```

## Usage

### Import and Initialize the Library

```typescript
import RSAKeyService from "ephy-rsa";

(async () => {
  const rsaService = await RSAKeyService();
  console.log("Public Key:", rsaService.getPublicKey());
})();
```

### Encrypt Data with a Server Public Key

```typescript
(async () => {
  const rsaService = await RSAKeyService();

  const serverPublicKey = "your-server-public-key-in-JWK-or-PEM-format";
  const encryptedData = await rsaService.encryptWithServerPublicKey(
    "Sensitive Data",
    serverPublicKey,
  );
  console.log("Encrypted Data:", encryptedData);
})();
```

### Decrypt Data with the Ephemeral Private Key

```typescript
(async () => {
  const rsaService = await RSAKeyService();

  const encryptedData = "..."; // Encrypted string received from backend
  const decryptedData = await rsaService.decryptWithPrivateKey(encryptedData);

  console.log("Decrypted Data:", decryptedData);
})();
```

## API Reference

### `RSAKeyService(algorithm?: RsaHashedKeyGenParams): Promise<RSAKeyService>`

Returns an instance of `RSAKeyService`. Optionally, you can specify an RSA key generation algorithm.

### `getPublicKey(): string | null`

Returns the **Base64-encoded PEM public key** of the generated RSA key pair.

### `encryptWithServerPublicKey(data: string, jwkPublicKey: JsonWebKey | string, alg?: "RSA-OAEP" | "RSA-OAEP-256", enc?: "A128GCM" | "A256GCM"): Promise<string>`

Encrypts data using a **server-provided public key**. Accepts JWK or PEM/Base64 formatted keys.

### `decryptWithPrivateKey(encryptedData: string): Promise<string>`

Decrypts the given encrypted data using the ephemeral private key stored in memory.

## TypeScript Interface

To provide better clarity, here's a possible `RSAKeyService` TypeScript interface:

```typescript
interface RSAKeyService {
  getPublicKey(): string | null;
  encryptWithServerPublicKey(
    data: string,
    jwkPublicKey: JsonWebKey | string,
    alg?: "RSA-OAEP" | "RSA-OAEP-256",
    enc?: "A128GCM" | "A256GCM",
  ): Promise<string>;
  decryptWithPrivateKey(encryptedData: string): Promise<string>;
}
```

## Security Considerations

- **Private keys are never stored persistently** – they exist only in memory and are lost when the page is refreshed.
- **Ensure your frontend is protected against XSS attacks**, as in-memory keys can be accessed if malicious scripts are injected.
- **Use HTTPS** to prevent man-in-the-middle attacks.
- **Implement a strong Content Security Policy (CSP)** to restrict script execution and mitigate injection risks.
