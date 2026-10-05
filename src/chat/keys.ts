import {
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
  type JsonWebKey,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** A local DIDComm identity: a did:key DID and its X25519 key-agreement secret (JWK). */
export interface Identity {
  did: string;
  secretJwk: JsonWebKey;
}

/** On-disk shape when the identity file is encrypted at rest. */
interface EncryptedIdentityFile {
  encrypted: true;
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

const STORE_DIR = join(process.cwd(), ".didcomm-ts");
const STORE_FILE_NAME = "identity.json";

const PASSPHRASE_ENV_VAR = "DIDCOMM_TS_PASSPHRASE";
const SCRYPT_KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, SCRYPT_KEY_LENGTH);
}

function encryptIdentity(identity: Identity, passphrase: string): EncryptedIdentityFile {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(passphrase, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(identity), "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    encrypted: true,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function decryptIdentity(
  file: EncryptedIdentityFile,
  passphrase: string,
  storeFile: string,
): Identity {
  const salt = Buffer.from(file.salt, "base64");
  const iv = Buffer.from(file.iv, "base64");
  const authTag = Buffer.from(file.authTag, "base64");
  const ciphertext = Buffer.from(file.ciphertext, "base64");
  const key = deriveKey(passphrase, salt);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString("utf8")) as Identity;
  } catch {
    throw new Error(
      `failed to decrypt identity at ${storeFile}: wrong ${PASSPHRASE_ENV_VAR} or corrupted file`,
    );
  }
}

// did:key multicodec prefix for an X25519 public key (code 0xec, varint-encoded),
// per https://github.com/multiformats/multicodec/blob/master/table.csv.
const X25519_PUB_MULTICODEC_PREFIX = Uint8Array.from([0xec, 0x01]);

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(bytes: Uint8Array): string {
  let num = 0n;
  for (const byte of bytes) num = (num << 8n) + BigInt(byte);

  let body = "";
  while (num > 0n) {
    body = BASE58_ALPHABET[Number(num % 58n)] + body;
    num /= 58n;
  }

  let leadingZeros = 0;
  for (const byte of bytes) {
    if (byte !== 0) break;
    leadingZeros++;
  }

  return "1".repeat(leadingZeros) + (body || "1");
}

function didKeyFromX25519PublicJwk(jwk: JsonWebKey): string {
  if (!jwk.x) throw new Error("X25519 public JWK is missing 'x'");
  const publicKeyBytes = Buffer.from(jwk.x, "base64url");
  const prefixed = new Uint8Array(X25519_PUB_MULTICODEC_PREFIX.length + publicKeyBytes.length);
  prefixed.set(X25519_PUB_MULTICODEC_PREFIX, 0);
  prefixed.set(publicKeyBytes, X25519_PUB_MULTICODEC_PREFIX.length);
  return `did:key:z${base58btcEncode(prefixed)}`;
}

function base58btcDecode(input: string): Uint8Array {
  let num = 0n;
  for (const char of input) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`invalid base58 character: ${char}`);
    num = num * 58n + BigInt(index);
  }

  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }

  let leadingOnes = 0;
  for (const char of input) {
    if (char !== "1") break;
    leadingOnes++;
  }

  return new Uint8Array([...new Array(leadingOnes).fill(0), ...bytes]);
}

/** The key-agreement verification method fragment this package uses for a did:key DID. */
export function didKeyFragment(did: string): string {
  const multibaseValue = did.slice("did:key:".length);
  return `${did}#${multibaseValue}`;
}

/**
 * Resolves a `did:key` DID (produced by `generateIdentity` above — an X25519
 * key-agreement public key, multicodec-prefixed and base58btc-encoded, with
 * no separate controller/signing key) back into its public key JWK.
 */
export function didKeyToX25519PublicJwk(did: string): JsonWebKey {
  if (!did.startsWith("did:key:z")) {
    throw new Error(`not a supported did:key DID: ${did}`);
  }
  const decoded = base58btcDecode(did.slice("did:key:z".length));
  const prefix = decoded.slice(0, X25519_PUB_MULTICODEC_PREFIX.length);
  if (!prefix.every((byte, i) => byte === X25519_PUB_MULTICODEC_PREFIX[i])) {
    throw new Error(`unsupported multicodec prefix for did:key DID: ${did}`);
  }
  const publicKeyBytes = decoded.slice(X25519_PUB_MULTICODEC_PREFIX.length);
  return { kty: "OKP", crv: "X25519", x: Buffer.from(publicKeyBytes).toString("base64url") };
}

function generateIdentity(): Identity {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
  const secretJwk = privateKey.export({ format: "jwk" }) as JsonWebKey;
  return { did: didKeyFromX25519PublicJwk(publicJwk), secretJwk };
}

/**
 * Loads the local identity from `.didcomm-ts/identity.json` (relative to
 * the current working directory, or `storeDirOverride` when given),
 * generating and persisting a new did:key identity on first run.
 *
 * When `DIDCOMM_TS_PASSPHRASE` is set, a newly created identity is
 * encrypted at rest with AES-256-GCM, keyed by scrypt-deriving that
 * passphrase against a random per-identity salt. When it is not set, the
 * identity is stored as plaintext JSON, as before.
 */
export function loadOrCreateIdentity(storeDirOverride?: string): Identity {
  const storeDir = storeDirOverride ?? STORE_DIR;
  const storeFile = join(storeDir, STORE_FILE_NAME);
  const passphrase = process.env[PASSPHRASE_ENV_VAR];

  if (!passphrase) {
    console.warn(
      `${PASSPHRASE_ENV_VAR} is not set; the identity at ${storeFile} is stored as plaintext ` +
        `JSON. Set ${PASSPHRASE_ENV_VAR} to encrypt it at rest for anything beyond local testing.`,
    );
  }

  if (existsSync(storeFile)) {
    const parsed = JSON.parse(readFileSync(storeFile, "utf8")) as
      | Identity
      | EncryptedIdentityFile;

    if ((parsed as EncryptedIdentityFile).encrypted === true) {
      if (!passphrase) {
        throw new Error(
          `identity at ${storeFile} is encrypted but ${PASSPHRASE_ENV_VAR} is not set`,
        );
      }
      return decryptIdentity(parsed as EncryptedIdentityFile, passphrase, storeFile);
    }

    if (passphrase) {
      console.warn(
        `identity at ${storeFile} is unencrypted; ${PASSPHRASE_ENV_VAR} will only be applied ` +
          "to new identities created on this machine, not to this existing one.",
      );
    }
    return parsed as Identity;
  }

  const identity = generateIdentity();
  mkdirSync(storeDir, { recursive: true, mode: 0o700 });
  const contents = passphrase ? encryptIdentity(identity, passphrase) : identity;
  writeFileSync(storeFile, JSON.stringify(contents, null, 2), { mode: 0o600 });
  return identity;
}
