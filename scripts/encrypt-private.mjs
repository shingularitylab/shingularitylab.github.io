import {
  createCipheriv,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";
import {
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

const ITERATIONS = 310_000;
const PRIVATE_DIR = resolve("private");
const OUTPUT_DIR = resolve("public", "secure");

const UNLOCK_TEXT = Buffer.from(
  "SHINGULARITY_TIMETABLE_OK",
  "utf8",
);

function encrypt(data, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);

  const key = pbkdf2Sync(
    password,
    salt,
    ITERATIONS,
    32,
    "sha256",
  );

  const cipher = createCipheriv(
    "aes-256-gcm",
    key,
    iv,
  );

  const ciphertext = Buffer.concat([
    cipher.update(data),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  // Web Crypto expects the GCM authentication tag appended to ciphertext.
  const ciphertextWithTag = Buffer.concat([
    ciphertext,
    authTag,
  ]);

  return {
    v: 1,
    kdf: "PBKDF2-SHA256",
    cipher: "AES-256-GCM",
    iterations: ITERATIONS,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    ciphertext: ciphertextWithTag.toString("base64"),
  };
}

async function writeEncrypted(
  filename,
  data,
  password,
) {
  const envelope = encrypt(data, password);

  await writeFile(
    resolve(OUTPUT_DIR, filename),
    JSON.stringify(envelope),
    "utf8",
  );
}

const rl = createInterface({ input, output });

try {
  console.log("");
  console.log("Shingularity Lab private timetable encryption");
  console.log("--------------------------------------------");
  console.log(
    "The password is NOT written into the repository.",
  );
  console.log("");

  const password = await rl.question(
    "Password: ",
  );

  const confirm = await rl.question(
    "Password again: ",
  );

  if (!password) {
    throw new Error("Password cannot be empty.");
  }

  if (password !== confirm) {
    throw new Error("Passwords do not match.");
  }

  const timetable = await readFile(
    resolve(PRIVATE_DIR, "timetable.png"),
  );

  const members = await readFile(
    resolve(PRIVATE_DIR, "members.json"),
  );

  // Validate JSON before encrypting it.
  JSON.parse(members.toString("utf8"));

  await mkdir(OUTPUT_DIR, {
    recursive: true,
  });

  await Promise.all([
    writeEncrypted(
      "unlock.enc",
      UNLOCK_TEXT,
      password,
    ),
    writeEncrypted(
      "timetable.enc",
      timetable,
      password,
    ),
    writeEncrypted(
      "members.enc",
      members,
      password,
    ),
  ]);

  console.log("");
  console.log("Created:");
  console.log("  public/secure/unlock.enc");
  console.log("  public/secure/timetable.enc");
  console.log("  public/secure/members.enc");
  console.log("");
  console.log(
    "Do NOT commit the private/ directory.",
  );
} finally {
  rl.close();
}
