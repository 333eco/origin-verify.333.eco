// The arithmetic everything else stands on. Browser and Node alike: WebCrypto and Uint8Array only, no Node modules and no Buffer.
// SHA-256 is written out because a Merkle tree needs it synchronously and thousands of times; signatures go through WebCrypto.

export const utf8 = (s) => new TextEncoder().encode(s);
export const text = (b) => new TextDecoder().decode(b);
export const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};
export const eq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; };
export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s) => { const o = new Uint8Array(s.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16); return o; };
export const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const b64u = (s) => b64(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
export const toB64 = (b) => { let s = ""; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s); };
export const toB64u = (b) => toB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };
export const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
export function sha256(...parts) {
  const m = parts.length === 1 ? parts[0] : concat(...parts);
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const full = Math.floor((m.length + 9 + 63) / 64) * 64, tail = new Uint8Array(full - Math.floor(m.length / 64) * 64);
  tail.set(m.subarray(Math.floor(m.length / 64) * 64));
  tail[m.length % 64] = 0x80;
  const dv = new DataView(tail.buffer);
  dv.setUint32(tail.length - 8, Math.floor(m.length / 2 ** 29));
  dv.setUint32(tail.length - 4, (m.length << 3) >>> 0);
  const w = new Uint32Array(64);
  const block = (b, o) => {
    for (let t = 0; t < 16; t++) w[t] = (b[o + t * 4] << 24) | (b[o + t * 4 + 1] << 16) | (b[o + t * 4 + 2] << 8) | b[o + t * 4 + 3];
    for (let t = 16; t < 64; t++) {
      const a = w[t - 15], c = w[t - 2];
      w[t] = (((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3)) + w[t - 7] + (((c >>> 17) | (c << 15)) ^ ((c >>> 19) | (c << 13)) ^ (c >>> 10)) + w[t - 16];
    }
    let [a, bb, c, d, e, f, g, hh] = h;
    for (let t = 0; t < 64; t++) {
      const t1 = (hh + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K[t] + w[t]) | 0;
      const t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & bb) ^ (a & c) ^ (bb & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  };
  for (let o = 0; o + 64 <= m.length; o += 64) block(m, o);
  for (let o = 0; o < tail.length; o += 64) block(tail, o);
  const out = new Uint8Array(32), odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i]);
  return out;
}
export function hmacSha256(key, ...parts) {
  const k = new Uint8Array(64);
  k.set(key.length > 64 ? sha256(key) : key);
  return sha256(k.map((x) => x ^ 0x5c), sha256(k.map((x) => x ^ 0x36), ...parts));
}

// ── Ed25519 ──────────────────────────────────────────────────────────────────────────────────────────────────────
// RFC 8032 verification by hand, for browsers whose WebCrypto lacks it (Chrome before 137, and the Android floor is Chrome 113).
// It handles only public values, so a timing leak gives nothing away.
const P = (1n << 255n) - 19n, L = (1n << 252n) + 27742317777372353535851937790883648493n, D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n, I = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
const mod = (a, m = P) => { const r = a % m; return r < 0n ? r + m : r; };
const pow = (b, e, m = P) => { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
const addPt = ([x1, y1, z1, t1], [x2, y2, z2, t2]) => {
  const a = mod((y1 - x1) * (y2 - x2)), b = mod((y1 + x1) * (y2 + x2)), c = mod(2n * t1 * t2 * D), d = mod(2n * z1 * z2), e = b - a, f = d - c, g = d + c, h = b + a;
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
};
const mulPt = (s, pt) => { let q = [0n, 1n, 1n, 0n]; while (s > 0n) { if (s & 1n) q = addPt(q, pt); pt = addPt(pt, pt); s >>= 1n; } return q; };
const leInt = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) + BigInt(b[i]); return n; };
function decodePt(b) {
  if (b.length !== 32) return null;
  const y = leInt(b) & ((1n << 255n) - 1n), sign = b[31] >> 7;
  if (y >= P) return null;
  const y2 = mod(y * y), u = mod(y2 - 1n), v = mod(D * y2 + 1n);
  let x = pow(mod(u * pow(v, P - 2n)), (P + 3n) / 8n);
  if (mod(v * x * x - u) !== 0n) { x = mod(x * I); if (mod(v * x * x - u) !== 0n) return null; }
  if (x === 0n && sign) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return [x, y, 1n, mod(x * y)];
}
const BASE = decodePt(unhex("5866666666666666666666666666666666666666666666666666666666666666"));
const samePt = ([x1, y1, z1], [x2, y2, z2]) => mod(x1 * z2 - x2 * z1) === 0n && mod(y1 * z2 - y2 * z1) === 0n;
export async function ed25519ByHand(pub, msg, sig) {
  if (sig.length !== 64) return false;
  const A = decodePt(pub), R = decodePt(sig.subarray(0, 32)), S = leInt(sig.subarray(32));
  if (!A || !R || S >= L) return false;
  const k = mod(leInt(new Uint8Array(await crypto.subtle.digest("SHA-512", concat(sig.subarray(0, 32), pub, msg)))), L);
  return samePt(mulPt(S, BASE), addPt(R, mulPt(k, A)));
}
let hasEd25519;
export async function ed25519(pub, msg, sig) {
  if (hasEd25519 === undefined) {
    try { await crypto.subtle.importKey("raw", new Uint8Array(32).fill(1), { name: "Ed25519" }, false, ["verify"]); hasEd25519 = true; } catch { hasEd25519 = false; }
  }
  if (!hasEd25519) return ed25519ByHand(pub, msg, sig);
  try { return await crypto.subtle.verify({ name: "Ed25519" }, await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]), sig, msg); }
  catch { return false; }
}

// ── DER: just the reading a signature check needs ────────────────────────────────────────────────────────────────
/** One node: its tag, its value, and the whole encoding (a signature covers the encoding, so it must never be rebuilt). */
export function der(b, at = 0) {
  if (at + 2 > b.length) throw new Error("DER: truncated");
  const tag = b[at];
  let len = b[at + 1], head = 2;
  if (len & 0x80) { const n = len & 0x7f; if (n === 0 || n > 4) throw new Error("DER: bad length"); len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[at + 2 + i]; head += n; }
  const end = at + head + len;
  if (end > b.length) throw new Error("DER: truncated");
  return { tag, value: b.subarray(at + head, end), raw: b.subarray(at, end), end };
}
export const kids = (node) => { const out = []; for (let i = 0; i < node.value.length;) { const k = der(node.value, i); out.push(k); i = k.end; } return out; };
export const oid = (node) => {
  const v = node.value; let s = `${Math.min(Math.floor(v[0] / 40), 2)}.${v[0] < 80 ? v[0] % 40 : v[0] - 80}`, n = 0;
  for (let i = 1; i < v.length; i++) { n = n * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { s += `.${n}`; n = 0; } }
  return s;
};
/** ECDSA in DER → the fixed r‖s WebCrypto wants. */
export function derSigToRaw(sig, size) {
  const seq = der(sig), parts = kids(seq);
  if (seq.tag !== 0x30 || seq.end !== sig.length || parts.length !== 2 || parts.some((k) => k.tag !== 0x02)) throw new Error("not an ECDSA signature");
  const [r, s] = parts.map((k) => k.value);
  const part = (x) => { let i = 0; while (i < x.length - 1 && x[i] === 0) i++; const v = x.subarray(i); if (v.length > size) throw new Error("ECDSA value too long"); const o = new Uint8Array(size); o.set(v, size - v.length); return o; };
  return concat(part(r), part(s));
}
