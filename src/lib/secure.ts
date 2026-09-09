const SESSION_PASSWORD_KEY = "shingularity.lab.private.session";
const UNLOCK_TEXT = "SHINGULARITY_TIMETABLE_OK";

interface Envelope {
  v: number;
  kdf: "PBKDF2-SHA256";
  cipher: "AES-256-GCM";
  iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(password);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    },
    keyMaterial,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["decrypt"],
  );
}

export async function decryptEnvelope(
  rawEnvelope: string,
  password: string,
): Promise<ArrayBuffer> {
  const envelope = JSON.parse(rawEnvelope) as Envelope;

  if (
    envelope.v !== 1 ||
    envelope.kdf !== "PBKDF2-SHA256" ||
    envelope.cipher !== "AES-256-GCM"
  ) {
    throw new Error("Unsupported encrypted payload.");
  }

  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const ciphertext = base64ToBytes(envelope.ciphertext);

  const key = await deriveKey(
    password,
    salt,
    envelope.iterations,
  );

  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128,
    },
    key,
    ciphertext,
  );
}

export async function decryptTextFromUrl(
  url: string,
  password: string,
): Promise<string> {
  const response = await fetch(url, {
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Unable to load ${url}`);
  }

  const envelope = await response.text();
  const plaintext = await decryptEnvelope(envelope, password);

  return new TextDecoder().decode(plaintext);
}

export async function validatePassword(
  password: string,
): Promise<boolean> {
  try {
    const text = await decryptTextFromUrl(
      "/secure/unlock.enc",
      password,
    );

    return text === UNLOCK_TEXT;
  } catch {
    return false;
  }
}

export function setSessionPassword(password: string): void {
  sessionStorage.setItem(SESSION_PASSWORD_KEY, password);
  window.dispatchEvent(new CustomEvent("shingularity:unlocked"));
}

export function getSessionPassword(): string | null {
  return sessionStorage.getItem(SESSION_PASSWORD_KEY);
}

export function clearSessionPassword(): void {
  sessionStorage.removeItem(SESSION_PASSWORD_KEY);
}
