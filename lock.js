/* Password locking for category sets, shared by the game (index.html) and the
   locker (../locker.html).

   A password is stretched with PBKDF2 into 48 bytes: the first 32 are the AES-GCM
   key that encrypts the set, the last 16 (as hex) are the set's file name. So a
   file name reveals nothing, and only the right password finds and opens a set.
   The many iterations make each password guess slow. */
const LOCK_ITERATIONS = 600000;
const LOCK_SALT = "category-merge-v1";

// "  Velvet  Otter " and "velvet otter" are the same password.
function normalizePassword(pw) {
  return pw.trim().toLowerCase().replace(/\s+/g, " ");
}

async function deriveLock(pw) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey(
    "raw", enc.encode(normalizePassword(pw)), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(LOCK_SALT), iterations: LOCK_ITERATIONS },
    base, 48 * 8));
  const key = await crypto.subtle.importKey(
    "raw", bits.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
  const id = Array.from(bits.slice(32), b => b.toString(16).padStart(2, "0")).join("");
  return { key, id };
}

function bytesToBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// data: { title, categories }. Returns the file name and contents for sets/.
async function lockSet(pw, data) {
  const { key, id } = await deriveLock(pw);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(data));
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  const blob = new Uint8Array(iv.length + sealed.length);
  blob.set(iv);
  blob.set(sealed, iv.length);
  return {
    file: id + ".js",
    text: `registerLockedSet("${bytesToBase64(blob)}");\n`
  };
}

// Throws if the key does not match or the file was changed.
async function unlockSet(key, b64) {
  const blob = base64ToBytes(b64);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.subarray(0, 12) }, key, blob.subarray(12));
  return JSON.parse(new TextDecoder().decode(plain));
}
