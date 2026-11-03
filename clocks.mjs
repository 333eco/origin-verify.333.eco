// The outside clocks, checked with no help: RFC 3161 tokens against pinned roots, and OpenTimestamps proofs against Bitcoin headers.
// ⛔ Neither says who did anything. A token says this hash existed by this time, on the authority's word; a block says it existed by that block.
import { concat, der, derSigToRaw, eq, hex, kids, oid, sha256, text } from "./primitives.mjs";

const HASHES = { "2.16.840.1.101.3.4.2.1": "SHA-256", "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512", "1.3.14.3.2.26": "SHA-1" };
const SIG_HASH = { "1.2.840.113549.1.1.11": "SHA-256", "1.2.840.113549.1.1.12": "SHA-384", "1.2.840.113549.1.1.13": "SHA-512", "1.2.840.10045.4.3.2": "SHA-256", "1.2.840.10045.4.3.3": "SHA-384", "1.2.840.10045.4.3.4": "SHA-512" };
const OID_RSA = "1.2.840.113549.1.1.1", OID_PSS = "1.2.840.113549.1.1.10", OID_EC = "1.2.840.10045.2.1";
const CURVES = { "1.2.840.10045.3.1.7": ["P-256", 32], "1.3.132.0.34": ["P-384", 48], "1.3.132.0.35": ["P-521", 66] };
const digest = async (name, data) => new Uint8Array(await crypto.subtle.digest(name, data));

function parseTime(n) {
  const s = text(n.value), m = n.tag === 0x17 ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/.exec(s) : /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.\d+)?Z$/.exec(s);
  if (!m) throw new Error("a time this reader does not know");
  const year = n.tag === 0x17 ? (Number(m[1]) >= 50 ? 1900 : 2000) + Number(m[1]) : Number(m[1]);
  return Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}
function parseCert(rawDer) {
  const cert = der(rawDer), [tbs, sigAlg, sigBits] = kids(cert), t = kids(tbs);
  let i = t[0].tag === 0xa0 ? 1 : 0;
  const serial = t[i], issuer = t[i + 2], validity = kids(t[i + 3]), subject = t[i + 4], spki = t[i + 5];
  const out = { raw: cert.raw, tbs: tbs.raw, sigAlg: kids(sigAlg), signature: sigBits.value.subarray(1), serial: serial.value, issuer: issuer.raw, subject: subject.raw, spki: spki.raw, notBefore: parseTime(validity[0]), notAfter: parseTime(validity[1]), ca: false, eku: [], ski: null };
  const ext = t.find((n) => n.tag === 0xa3);
  if (ext) for (const e of kids(kids(ext)[0])) {
    const parts = kids(e), id = oid(parts[0]), value = der(parts[parts.length - 1].value);
    if (id === "2.5.29.19") out.ca = kids(value).some((k) => k.tag === 0x01 && k.value[0] !== 0);
    if (id === "2.5.29.37") out.eku = kids(value).map(oid);
    if (id === "2.5.29.14") out.ski = value.value;
  }
  return out;
}
/** A signature under a certificate's public key, whichever of the algorithms a TSA uses. `hashName` comes from the signature algorithm or SignerInfo. */
async function checkSig(spkiDer, algKids, signature, data, signerDigest) {
  const spki = kids(der(spkiDer)), keyAlg = kids(spki[0]), keyOid = oid(keyAlg[0]), sigOid = oid(algKids[0]);
  if (keyOid === OID_EC) {
    const [curve, size] = CURVES[oid(keyAlg[1])] ?? [];
    if (!curve) throw new Error("an unknown curve");
    const hash = SIG_HASH[sigOid] ?? signerDigest;
    return crypto.subtle.verify({ name: "ECDSA", hash }, await crypto.subtle.importKey("spki", spkiDer, { name: "ECDSA", namedCurve: curve }, false, ["verify"]), derSigToRaw(signature, size), data);
  }
  if (keyOid !== OID_RSA && keyOid !== OID_PSS) throw new Error("an unknown key type");
  if (sigOid === OID_PSS) {
    const p = kids(algKids[1]), hashAlg = kids(kids(p[0])[0]), hash = HASHES[oid(hashAlg[0])], salt = p.find((n) => n.tag === 0xa2);
    const saltLength = salt ? kids(salt)[0].value.reduce((a, b) => a * 256 + b, 0) : 20;
    return crypto.subtle.verify({ name: "RSA-PSS", saltLength }, await crypto.subtle.importKey("spki", spkiDer, { name: "RSA-PSS", hash }, false, ["verify"]), signature, data);
  }
  const hash = SIG_HASH[sigOid] ?? (sigOid === OID_RSA ? signerDigest : null);
  if (!hash) throw new Error(`a signature algorithm this reader refuses: ${sigOid}`);
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", await crypto.subtle.importKey("spki", spkiDer, { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]), signature, data);
}

/**
 * RFC 3161 and CMS by hand: the token's hash is this data's, the authority signed that token, and its certificate leads to a root the caller pinned.
 * Certificates are judged at the token's own time, because an archive outlives them. ⚠️ Revocation is not checked: that would need the network and the CA's cooperation.
 * ⚠️ A token has parts nobody signs (status text, the digest list, spare copies of certificates), so a changed byte there passes, and rightly: nothing here reads meaning from them.
 */
export async function checkTimestamp(tsr, data, rootsDer) {
  const fail = (why) => ({ ok: false, why });
  try {
    const top = der(tsr);
    if (top.tag !== 0x30 || top.end !== tsr.length) return fail("not a time stamp response");
    const resp = kids(top);
    const status = kids(resp[0])[0].value.reduce((a, b) => a * 256 + b, 0);
    if (status > 1) return fail(`the authority refused: status ${status}`);
    if (!resp[1]) return fail("the response carries no token");
    const content = kids(resp[1]);
    if (oid(content[0]) !== "1.2.840.113549.1.7.2") return fail("the token is not signed data");
    const signed = kids(kids(content[1])[0]);
    const encap = kids(signed[2]);
    if (oid(encap[0]) !== "1.2.840.113549.1.9.16.1.4") return fail("the token holds something other than a time stamp");
    const inner = kids(encap[1])[0];
    if (inner.tag !== 0x04) return fail("the token's contents are not an octet string");
    const eContent = inner.value;
    const info = kids(der(eContent)), imprint = kids(info[2]);
    if (oid(kids(imprint[0])[0]) !== "2.16.840.1.101.3.4.2.1") return fail("the token's hash is not SHA-256");
    if (!eq(imprint[1].value, sha256(data))) return fail("the token speaks of different data");
    const genNode = info.find((n) => n.tag === 0x18);
    if (!genNode) return fail("the token states no time");
    const time = parseTime(genNode);

    const certs = (signed.find((n) => n.tag === 0xa0) ? kids(signed.find((n) => n.tag === 0xa0)) : []).filter((n) => n.tag === 0x30).map((n) => parseCert(n.raw));
    const signerInfo = kids(kids(signed[signed.length - 1])[0]);
    const sid = signerInfo[1];
    let leaf;
    if (sid.tag === 0x80) leaf = certs.find((c) => c.ski && eq(c.ski, sid.value));
    else { const [iss, ser] = kids(sid); leaf = certs.find((c) => eq(c.issuer, iss.raw) && eq(c.serial, ser.value)); }
    if (!leaf) return fail("the token does not carry its signer's certificate");

    const signedAttrs = signerInfo.find((n) => n.tag === 0xa0);
    const hashName = HASHES[oid(kids(signerInfo[2])[0])];
    if (!signedAttrs || !hashName || hashName === "SHA-1") return fail("the token's digest is not one this reader accepts");
    const md = kids(signedAttrs).find((a) => oid(kids(a)[0]) === "1.2.840.113549.1.9.4");
    if (!md || !eq(der(kids(kids(md)[1])[0].raw).value, await digest(hashName, eContent))) return fail("the signed digest does not match the token");
    const asSet = concat(new Uint8Array([0x31]), signedAttrs.raw.subarray(1)); // the signature covers the attributes as a SET (RFC 5652 §5.4)
    const after = signerInfo.indexOf(signedAttrs), sigAlg = kids(signerInfo[after + 1]), signature = signerInfo[after + 2].value;
    if (!(await checkSig(leaf.spki, sigAlg, signature, asSet, hashName))) return fail("the authority's signature does not verify");
    if (!leaf.eku.includes("1.3.6.1.5.5.7.3.8")) return fail("the signer's certificate is not for time stamping");

    const roots = rootsDer.map(parseCert);
    const pool = [...certs, ...roots];
    let cur = leaf;
    for (let depth = 0; depth < 8; depth++) {
      if (time < cur.notBefore || time > cur.notAfter) return fail("a certificate was not valid at the token's time");
      if (roots.some((r) => eq(r.raw, cur.raw))) return { ok: true, time: new Date(time).toISOString() };
      const candidates = pool.filter((c) => eq(c.subject, cur.issuer) && !eq(c.raw, cur.raw));
      let next = null;
      for (const c of candidates) { try { if (c.ca && await checkSig(c.spki, cur.sigAlg, cur.signature, cur.tbs)) { next = c; break; } } catch { /* try the next one */ } }
      if (!next) return fail("the certificate chain does not reach a pinned root");
      cur = next;
    }
    return fail("the certificate chain is too long");
  } catch (e) { return fail(`the token cannot be read: ${e.message}`); }
}

// ── OpenTimestamps ───────────────────────────────────────────────────────────────────────────────────────────────
const OTS_MAGIC = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294";
const TAG_PENDING = "83dfe30d2ef90c8e", TAG_BITCOIN = "0588960d73d71901";
function reader(b) {
  let i = 0;
  const byte = () => { if (i >= b.length) throw new Error("truncated"); return b[i++]; };
  const bytes = (n) => { if (i + n > b.length) throw new Error("truncated"); const v = b.subarray(i, i + n); i += n; return v; };
  const varuint = () => { let v = 0, s = 0, c; do { c = byte(); v += (c & 0x7f) * 2 ** s; s += 7; if (s > 49) throw new Error("varuint too long"); } while (c & 0x80); return v; };
  return { byte, bytes, varuint, varbytes: () => bytes(varuint()), at: () => i, done: () => i === b.length };
}
function walk(r, msg, out, depth = 0) {
  if (depth > 256) throw new Error("too deep");
  const one = (tag) => {
    if (tag === 0x00) {
      const t = hex(r.bytes(8)), payload = reader(r.varbytes());
      if (t === TAG_BITCOIN) out.bitcoin.push({ height: payload.varuint(), msg });
      else if (t === TAG_PENDING) out.pending.push(text(payload.varbytes()));
      return;
    }
    let next;
    if (tag === 0xf0) next = concat(msg, r.varbytes());
    else if (tag === 0xf1) next = concat(r.varbytes(), msg);
    else if (tag === 0x08) next = sha256(msg);
    else throw new Error(`an operation this reader does not know: ${tag}`);
    walk(r, next, out, depth + 1);
  };
  let tag = r.byte();
  while (tag === 0xff) { one(r.byte()); tag = r.byte(); }
  one(tag);
}
const sha256d = (b) => sha256(sha256(b));
/** A real header proves its own work; without this, anyone could supply a header holding whatever root they like. Height still comes from the header's source. */
function headerHasWork(h) {
  if (h.length !== 80) return false;
  const bits = (h[75] << 24) | (h[74] << 16) | (h[73] << 8) | h[72];
  const exp = bits >>> 24, mant = BigInt(bits & 0x007fffff), target = exp <= 3 ? mant >> BigInt(8 * (3 - exp)) : mant << BigInt(8 * (exp - 3));
  // Bitcoin's easiest target ever: nobody can claim work with an easier one.
  if (target <= 0n || target > 0xffffn << 208n) return false;
  const pow = sha256d(h); let v = 0n; for (let i = 31; i >= 0; i--) v = (v << 8n) + BigInt(pow[i]);
  return v <= target;
}
/**
 * `digest` is what the proof must speak of. Each Bitcoin line reads verified: true when the header (from `header(height)`) holds this branch's result, false when it does not, null when no header was given.
 * A pending line is only a calendar's promise, listed and never counted.
 */
export async function checkOts(proof, digest, { header } = {}) {
  try {
    const r = reader(proof);
    if (hex(r.bytes(31)) !== OTS_MAGIC) return { ok: false, why: "not an OpenTimestamps proof" };
    if (r.byte() !== 1 || r.byte() !== 0x08) return { ok: false, why: "not a version 1, SHA-256 proof" };
    if (!eq(r.bytes(32), digest)) return { ok: false, why: "the proof speaks of different data" };
    const seen = { bitcoin: [], pending: [] };
    walk(r, digest, seen);
    if (!r.done()) return { ok: false, why: "trailing bytes" };
    const bitcoin = [];
    for (const a of seen.bitcoin) {
      const h = header ? await header(a.height) : null;
      if (!h) { bitcoin.push({ height: a.height, verified: null }); continue; }
      const good = headerHasWork(h) && eq(h.subarray(36, 68), a.msg);
      const dv = new DataView(h.buffer, h.byteOffset, 80);
      bitcoin.push({ height: a.height, verified: good, ...(good ? { time: new Date(dv.getUint32(68, true) * 1000).toISOString() } : {}) });
    }
    return { ok: true, bitcoin, pending: [...new Set(seen.pending)] };
  } catch (e) { return { ok: false, why: `the proof cannot be read: ${e.message}` }; }
}
