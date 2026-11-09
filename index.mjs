// @333eco/origin-verify. CC0. Checks a B-Origin record with no help from its operator: no runtime dependencies, in a browser or in Node.
// ⚠️ Written apart from the service on purpose: it shares no code with services/b, and it checks proofs with RFC 9162's
// iterative algorithms where the service builds them with RFC 6962's recursion. One author's blind spots still apply.
import { b64, b64u, concat, der, derSigToRaw, ed25519, eq, hex, hmacSha256, sha256, text, toB64, toB64u, u32, u64, utf8 } from "./primitives.mjs";
import { checkOts, checkTimestamp } from "./clocks.mjs";
export { checkOts, checkTimestamp } from "./clocks.mjs";
export { hashFile, decodePng, phashOf, phashDistance } from "./media.mjs";
import { readEmbedded } from "./embed.mjs";
export { embedPack, readEmbedded } from "./embed.mjs";

const NODE = new Uint8Array([1]), LEAF = new Uint8Array([0]);
const odd = (n) => n % 2 === 1;
const half = (n) => Math.floor(n / 2);

export const hashLeaf = (entry) => sha256(LEAF, entry);
const hashNode = (l, r) => sha256(NODE, l, r);

/** RFC 8785, for the only values entries hold. */
export function canonical(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("non-integer number in an entry"); return String(v); }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}

/** RFC 9162 §2.1.3.2. */
export function checkInclusion(leaf, index, size, proof, root) {
  if (index < 0 || index >= size) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      r = hashNode(p, r);
      if (!odd(fn)) while (!odd(fn) && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else r = hashNode(r, p);
    fn = half(fn); sn = half(sn);
  }
  return sn === 0 && eq(r, root);
}
/** RFC 9162 §2.1.4.2. */
export function checkConsistency(first, second, proof, firstRoot, secondRoot) {
  if (first > second) return false;
  if (first === second) return proof.length === 0 && eq(firstRoot, secondRoot);
  if (first === 0) return proof.length === 0;
  if (proof.length === 0) return false;
  const path = Number.isInteger(Math.log2(first)) ? [firstRoot, ...proof] : proof;
  let fn = first - 1, sn = second - 1;
  while (odd(fn)) { fn = half(fn); sn = half(sn); }
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      fr = hashNode(c, fr); sr = hashNode(c, sr);
      if (!odd(fn)) while (!odd(fn) && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else sr = hashNode(sr, c);
    fn = half(fn); sn = half(sn);
  }
  return sn === 0 && eq(fr, firstRoot) && eq(sr, secondRoot);
}

// ── signed notes ─────────────────────────────────────────────────────────────────────────────────────────────────
function parseVkey(v) {
  const m = /^([^+\s]+)\+([0-9a-f]{8})\+(\S+)$/.exec(v);
  if (!m) throw new Error("bad vkey");
  const all = b64(m[3]), type = all[0], raw = all.subarray(1), id = Uint8Array.from(m[2].match(/../g), (x) => parseInt(x, 16));
  if (!eq(sha256(utf8(m[1] + "\n"), new Uint8Array([type]), raw).subarray(0, 4), id)) throw new Error("vkey hash mismatch");
  return { name: m[1], id, type, raw };
}
/** Splits a note into its text and signature lines. */
function parseNote(note) {
  const cut = note.indexOf("\n\n");
  if (cut < 0) throw new Error("not a signed note");
  const body = note.slice(0, cut + 1), sigs = [];
  for (const l of note.slice(cut + 2).split("\n")) {
    if (!l) continue;
    const m = /^— (\S+) (\S+)$/.exec(l);
    if (!m) throw new Error("bad signature line");
    sigs.push({ name: m[1], bytes: b64(m[2]) });
  }
  return { body, sigs };
}
/** The part of a checkpoint every clock stamps: it does not change as cosignatures arrive. */
export const checkpointBody = (note) => note.slice(0, note.indexOf("\n\n") + 1);

/** Checks the log's own signature; counts distinct witnesses with a good cosignature. A bad line is simply not counted. */
export async function checkCheckpoint(note, trust) {
  const { body, sigs } = parseNote(note);
  const [origin, size, root] = body.split("\n");
  if (origin !== trust.origin) return { ok: false, why: "another log's checkpoint" };
  if (!/^(0|[1-9]\d*)$/.test(size)) return { ok: false, why: "bad size" };
  const log = parseVkey(trust.logVkey), bodyBytes = utf8(body);
  const mine = sigs.find((s) => s.name === log.name && eq(s.bytes.subarray(0, 4), log.id));
  if (!mine || !(await ed25519(log.raw, bodyBytes, mine.bytes.subarray(4)))) return { ok: false, why: "the log's signature does not verify" };
  const witnesses = new Set();
  for (const v of trust.witnesses ?? []) {
    const w = parseVkey(v);
    if (w.type !== 0x04) continue;
    for (const s of sigs) {
      if (s.name !== w.name || s.bytes.length !== 76 || !eq(s.bytes.subarray(0, 4), w.id)) continue;
      const time = new DataView(s.bytes.buffer, s.bytes.byteOffset + 4, 8).getBigUint64(0);
      if (await ed25519(w.raw, utf8(`cosignature/v1\ntime ${time}\n${body}`), s.bytes.subarray(12))) witnesses.add(w.name);
    }
  }
  return { ok: true, size: Number(size), root: b64(root), body, witnesses: [...witnesses] };
}

// ── entries ──────────────────────────────────────────────────────────────────────────────────────────────────────
const DOMAIN = (t, v) => utf8(`b-origin/${t}/v${v}\0`);
const importP256 = (spki) => crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
/** The operator's witness signature over an entry. */
export async function checkWitnessSignature(entry, trust) {
  const key = trust.recordKeys?.[entry.kid];
  if (!key) return false;
  const { witnessSig, ...rest } = entry;
  if (typeof witnessSig !== "string") return false;
  try {
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await importP256(b64(key)), b64u(witnessSig), concat(DOMAIN(entry.t, entry.v), utf8(canonical(rest))));
  } catch { return false; }
}

// Just enough CBOR to read a COSE public key: maps, integers and byte strings.
function cborMap(buf) {
  let i = 0;
  const head = () => { const b = buf[i++], maj = b >> 5, a = b & 31; let n = a;
    if (a === 24) n = buf[i++]; else if (a === 25) { n = (buf[i] << 8) | buf[i + 1]; i += 2; } else if (a > 25) throw new Error("unsupported CBOR");
    return [maj, n]; };
  const item = () => { const [maj, n] = head();
    if (maj === 0) return n; if (maj === 1) return -1 - n;
    if (maj === 2) { const v = buf.subarray(i, i + n); i += n; return v; }
    if (maj === 5) { const m = new Map(); for (let k = 0; k < n; k++) { const key = item(); m.set(key, item()); } return m; }
    throw new Error("unsupported CBOR"); };
  return item();
}
/** A passkey's signature over `signed`, under the key type its COSE key names. */
async function checkCose(coseBytes, signed, signature) {
  const m = cborMap(coseBytes), alg = m.get(3);
  if (alg === -8) return ed25519(m.get(-2), signed, signature);
  if (alg === -7) {
    const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: toB64u(m.get(-2)), y: toB64u(m.get(-3)), ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derSigToRaw(signature, 32), signed);
  }
  if (alg === -257) {
    const key = await crypto.subtle.importKey("jwk", { kty: "RSA", n: toB64u(m.get(-1)), e: toB64u(m.get(-2)), ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signed);
  }
  throw new Error("unsupported key type");
}
const lp = (b) => concat(u32(b.length), b);

/**
 * SPEC §6.3. With a signer's opening, the proof stops depending on the operator: a passkey whose public key is X signed exactly this claim.
 * ⛔ It never says who imagined the work, or that a person holds one account.
 */
export async function checkReveal(entry, opening, trust) {
  const fail = (why) => ({ ok: false, why });
  const raw = Object.fromEntries(["salt", "nonce", "authenticatorData", "clientDataJSON", "signature", "credentialPublicKey"].map((k) => [k, b64u(String(opening?.[k] ?? ""))]));
  const commitment = sha256(utf8("b-origin/assertion/v1\0"), lp(raw.salt), lp(raw.authenticatorData), lp(raw.clientDataJSON), lp(raw.signature), lp(raw.credentialPublicKey));
  if (toB64u(commitment) !== entry.assertionCommitment) return fail("the opening does not match the record's commitment");
  const challenge = entry.t === "record"
    ? sha256(utf8("b-origin/claim/v1\0"), raw.nonce, sha256(utf8(canonical(entry.claim))))
    : entry.t === "withdraw" ? sha256(utf8("b-origin/withdraw/v1\0"), raw.nonce, u64(entry.target)) : null;
  if (!challenge) return fail("nothing to reveal in this entry");
  if (toB64u(challenge) !== entry.claimCommitment) return fail("the challenge does not bind this claim");
  let cd;
  try { cd = JSON.parse(text(raw.clientDataJSON)); } catch { return fail("bad client data"); }
  if (cd.type !== "webauthn.get" || cd.origin !== trust.webOrigin || cd.challenge !== entry.claimCommitment) return fail("the assertion was made elsewhere or for something else");
  const auth = raw.authenticatorData;
  if (auth.length < 37 || !eq(auth.subarray(0, 32), sha256(utf8(trust.rpId)))) return fail("the assertion names another site");
  if ((auth[32] & 0x05) !== 0x05) return fail("the passkey's owner was not present and verified");
  let good;
  try { good = await checkCose(raw.credentialPublicKey, concat(auth, sha256(raw.clientDataJSON)), raw.signature); } catch (e) { return fail(e.message); }
  if (!good) return fail("the passkey's signature does not verify");
  return { ok: true, passkeyPublicKey: opening.credentialPublicKey };
}
/** SPEC §6.4: which of these entries carry this person's tag. Anything here they did not make is a forgery to report. */
export function findMine(tagKey, entries) {
  const key = b64u(tagKey), out = [];
  for (const e of entries) {
    if (e.ownerTag === undefined) continue;
    if (toB64u(hmacSha256(key, utf8("b-origin/tag/v1\0"), u64(e.index))) === e.ownerTag) out.push(e.index);
  }
  return out;
}

// ── reading the log ──────────────────────────────────────────────────────────────────────────────────────────────
const tilePath = (kind, n, width) => {
  let s = "", v = n, first = true;
  do { const part = String(v % 1000).padStart(3, "0"); s = (first ? part : "x" + part + "/") + s; first = false; v = Math.floor(v / 1000); } while (v > 0);
  return `tile/${kind}/${s}${width ? `.p/${width}` : ""}`;
};
function entriesOf(bundle) {
  const out = [];
  for (let i = 0; i < bundle.length;) { const n = (bundle[i] << 8) | bundle[i + 1]; out.push(bundle.subarray(i + 2, i + 2 + n)); i += 2 + n; }
  return out;
}
const merkle = (hashes) => {
  if (hashes.length === 1) return hashes[0];
  let k = 1; while (k * 2 < hashes.length) k *= 2;
  return hashNode(merkle(hashes.slice(0, k)), merkle(hashes.slice(k)));
};
export const treeRoot = (leaves) => (leaves.length ? merkle(leaves) : sha256(new Uint8Array(0)));
/** Reads every entry at this size from public tiles. `get(path)` returns bytes or null. */
export async function readEntries(get, size) {
  const out = [];
  for (let n = 0; n * 256 < size; n++) {
    const width = n * 256 + 256 <= size ? undefined : size % 256;
    const b = await get(tilePath("entries", n, width));
    if (!b) throw new Error(`missing entry bundle ${n}`);
    const es = entriesOf(new Uint8Array(b));
    if (es.length !== (width ?? 256)) throw new Error(`entry bundle ${n} has the wrong length`);
    out.push(...es);
  }
  return out;
}
/**
 * The full audit: recompute the tree from every entry, and hold the published hash tiles to it.
 * A tile or bundle changed anywhere fails here. It costs a read of the whole log; a single record needs only checkInclusion.
 */
export async function auditLog(get, note, trust) {
  const cp = await checkCheckpoint(note, trust);
  if (!cp.ok) return { ok: false, why: cp.why };
  let entries;
  try { entries = await readEntries(get, cp.size); } catch (e) { return { ok: false, why: e.message }; }
  const leaves = entries.map(hashLeaf);
  if (!eq(treeRoot(leaves), cp.root)) return { ok: false, why: "the entries do not produce the checkpoint's root" };
  for (let n = 0; n * 256 < cp.size; n++) {
    const width = n * 256 + 256 <= cp.size ? undefined : cp.size % 256;
    const t = await get(tilePath(0, n, width));
    if (!t || !eq(new Uint8Array(t), concat(...leaves.slice(n * 256, n * 256 + (width ?? 256))))) return { ok: false, why: `hash tile ${n} does not match the entries` };
  }
  for (const [i, bytes] of entries.entries()) {
    const s = text(bytes), e = JSON.parse(s);
    if (e.index !== i) return { ok: false, why: `the entry at ${i} says it belongs at ${e.index}` };
    if (canonical(e) !== s) return { ok: false, why: `the entry at ${i} is not canonical` };
    if (e.t !== "void" && !(await checkWitnessSignature(e, trust))) return { ok: false, why: `the entry at ${i} has no valid witness signature` };
  }
  return { ok: true, size: cp.size, witnesses: cp.witnesses, entries: entries.length };
}
/** The inclusion proof for one entry, computed from the entries themselves. */
export function proofFor(leaves, index) {
  const path = (m, lo, hi) => {
    if (hi - lo === 1) return [];
    let k = 1; while (k * 2 < hi - lo) k *= 2;
    return m < k ? [...path(m, lo, lo + k), merkle(leaves.slice(lo + k, hi))] : [...path(m - k, lo + k, hi), merkle(leaves.slice(lo, lo + k))];
  };
  return path(index, 0, leaves.length);
}
/** RFC 6962 §2.1.2: that the first `first` leaves are a prefix of these. */
export function consistencyFor(leaves, first) {
  const sub = (m, lo, hi, whole) => {
    if (m === hi - lo) return whole ? [] : [merkle(leaves.slice(lo, hi))];
    let k = 1; while (k * 2 < hi - lo) k *= 2;
    return m <= k ? [...sub(m, lo, lo + k, whole), merkle(leaves.slice(lo + k, hi))] : [...sub(m - k, lo + k, hi, false), merkle(leaves.slice(lo, lo + k))];
  };
  return first === 0 || first === leaves.length ? [] : sub(first, 0, leaves.length, true);
}

/** Finds records of a file by what it still is. The whole log is public, so no lookup service learns what is being checked (SPEC §6.5). */
export async function findRecords(get, size, hashes, { maxDistance = 8 } = {}) {
  const { phashDistance } = await import("./media.mjs");
  const out = [], withdrawn = new Map();
  for (const bytes of await readEntries(get, size)) {
    const e = JSON.parse(text(bytes));
    if (e.t === "withdraw") { withdrawn.set(e.target, e.witnessedAt); continue; }
    if (e.t !== "record") continue;
    const c = e.claim;
    if (hashes.sha256 && c.sha256 === hashes.sha256) out.push({ index: e.index, how: "exact", entry: e });
    else if (hashes.pixels && c.pixels === hashes.pixels) out.push({ index: e.index, how: "same pixels", entry: e });
    else if (hashes.phash && c.phash) { const distance = phashDistance(hashes.phash, c.phash); if (distance <= maxDistance) out.push({ index: e.index, how: "similar", distance, entry: e }); }
  }
  return out.map((m) => (withdrawn.has(m.index) ? { ...m, withdrawnAt: withdrawn.get(m.index) } : m));
}

/**
 * Checks one bundle: { entry, checkpoint, inclusion: [base64…], opening? }. It needs no network and no operator.
 * Each state stands alone (§6.4). A failed check says so; it is never softened into a lesser state.
 */
export async function verifyBundle(bundle, trust) {
  const fail = (why) => ({ ok: false, why });
  const { entry, checkpoint, inclusion, opening } = bundle;
  if (!entry || !checkpoint || !Array.isArray(inclusion)) return fail("the bundle is incomplete");
  if (entry.t !== "record" && entry.t !== "withdraw") return fail("this entry is not a record");
  if (!(await checkWitnessSignature(entry, trust))) return fail("the witness signature does not verify");
  const cp = await checkCheckpoint(checkpoint, trust);
  if (!cp.ok) return fail(cp.why);
  const leaf = hashLeaf(utf8(canonical(entry)));
  if (!checkInclusion(leaf, entry.index, cp.size, inclusion.map((p) => b64(p)), cp.root)) return fail("the record is not in the tree this checkpoint signs");
  const quorum = trust.witnessQuorum ?? Infinity;
  const out = {
    ok: true, index: entry.index, size: cp.size, included: true,
    witnessed: cp.witnesses.length >= quorum, witnesses: cp.witnesses, quorum, witnessLabel: trust.witnessLabel,
    witnessedAt: entry.witnessedAt,
    conclusion: "The operator witnessed this claim at this time and cannot later remove it.",
  };
  if (opening) {
    const r = await checkReveal(entry, opening, trust);
    if (!r.ok) return fail(`reveal: ${r.why}`);
    out.revealed = true;
    out.conclusion = "A passkey whose public key is given here signed exactly this claim.";
    out.passkeyPublicKey = r.passkeyPublicKey;
  }
  return out;
}

// ── a pack: one record and everything needed to check it, offline, with no help from anyone ────────────────────────
const stampedAfter = (sizes, index) => (sizes ?? []).filter((s) => s > index).sort((a, b) => a - b)[0];
/** Gathers a pack from the public log. `header(height)` supplies Bitcoin block headers (80 bytes), so the pack keeps them too. */
export async function packRecord(get, index, trust, { opening, header } = {}) {
  const note = text(await get("checkpoint")), cp = await checkCheckpoint(note, trust);
  if (!cp.ok) throw new Error(cp.why);
  if (index >= cp.size) throw new Error("not yet in the tree: it joins at the next checkpoint");
  const entries = await readEntries(get, cp.size), leaves = entries.map(hashLeaf);
  const pack = { kind: "b-origin-pack", v: 1, entry: JSON.parse(text(entries[index])), checkpoint: note, inclusion: proofFor(leaves, index).map(toB64), ...(opening ? { opening } : {}), stamps: {} };
  const raw = await get("stamps/index.json"), list = raw ? JSON.parse(text(raw)) : {};
  const carry = async (kind, size) => {
    if (size === undefined) return null;
    const archived = text(await get(`checkpoints/${size}`));
    return { kind, size, checkpoint: archived, consistency: consistencyFor(leaves, size).map(toB64) };
  };
  const tsaAt = stampedAfter(list.tsa, index), otsAt = stampedAfter(list.ots, index);
  if (tsaAt !== undefined) {
    const c = await carry("tsa", tsaAt);
    pack.stamps.tsa = { size: c.size, checkpoint: c.checkpoint, consistency: c.consistency, tokens: {} };
    for (const name of Object.keys(trust.tsaRoots ?? {})) { const t = await get(`stamps/${tsaAt}.${name}.tsr`); if (t) pack.stamps.tsa.tokens[name] = toB64(new Uint8Array(t)); }
  }
  if (otsAt !== undefined) {
    const c = await carry("ots", otsAt), proof = await get(`stamps/${otsAt}.ots`);
    if (proof) {
      pack.stamps.ots = { size: c.size, checkpoint: c.checkpoint, consistency: c.consistency, proof: toB64(new Uint8Array(proof)), headers: {} };
      if (header) {
        const seen = await checkOts(new Uint8Array(proof), sha256(utf8(checkpointBody(c.checkpoint))));
        for (const a of seen.bitcoin ?? []) { const h = await header(a.height); if (h) pack.stamps.ots.headers[a.height] = toB64(h); }
      }
    }
  }
  return pack;
}
/** Proves a stamped checkpoint held this record, by showing it is a prefix of the tree that does. */
async function stampedCheckpoint(s, index, cp, trust) {
  const old = await checkCheckpoint(s.checkpoint, trust);
  if (!old.ok) return { ok: false, why: `the stamped checkpoint: ${old.why}` };
  if (old.size !== s.size || old.size <= index) return { ok: false, why: "the stamped checkpoint does not hold this record" };
  if (!checkConsistency(old.size, cp.size, (s.consistency ?? []).map(b64), old.root, cp.root)) return { ok: false, why: "the stamped checkpoint is not a prefix of this log" };
  return { ok: true, body: utf8(old.body) };
}
/**
 * Checks a pack. Each of the four states stands alone and none implies another: included · witnessed · timestamped · Bitcoin-anchored.
 * `now` never enters: an authority's token is judged at the time it states.
 */
export async function verifyPack(pack, trust, { header } = {}) {
  if (pack?.kind !== "b-origin-pack" || pack.v !== 1) return { ok: false, why: "not a B-Origin pack" };
  const out = await verifyBundle(pack, trust);
  if (!out.ok) return out;
  const cp = await checkCheckpoint(pack.checkpoint, trust);
  out.timestamped = []; out.timestampFailures = []; out.bitcoin = []; out.bitcoinPending = [];
  if (pack.stamps?.tsa) {
    const held = await stampedCheckpoint(pack.stamps.tsa, out.index, cp, trust);
    if (!held.ok) return { ok: false, why: `timestamp: ${held.why}` };
    for (const [name, token] of Object.entries(pack.stamps.tsa.tokens ?? {})) {
      const r = await checkTimestamp(b64(token), held.body, (trust.tsaRoots?.[name] ?? []).map(b64));
      if (r.ok) out.timestamped.push({ authority: name, noLaterThan: r.time }); else out.timestampFailures.push({ authority: name, why: r.why });
    }
  }
  if (pack.stamps?.ots) {
    const held = await stampedCheckpoint(pack.stamps.ots, out.index, cp, trust);
    if (!held.ok) return { ok: false, why: `Bitcoin: ${held.why}` };
    const r = await checkOts(b64(pack.stamps.ots.proof), sha256(held.body), {
      header: async (h) => { const saved = pack.stamps.ots.headers?.[h]; if (saved) return b64(saved); return header ? header(h) : null; },
    });
    if (!r.ok) return { ok: false, why: `Bitcoin: ${r.why}` };
    out.bitcoin = r.bitcoin.filter((a) => a.verified).map(({ height, time }) => ({ height, time }));
    out.bitcoinUnchecked = r.bitcoin.filter((a) => a.verified === null).map((a) => a.height);
    out.bitcoinPending = r.pending;
    const bad = r.bitcoin.find((a) => a.verified === false);
    if (bad) return { ok: false, why: `Bitcoin: block ${bad.height} does not commit to this proof` };
  }
  return out;
}

/**
 * Checks a file by the proof inside it, with no network. The proof counts only if taking it out gives back exactly the bytes the record names.
 * ⚠️ `withdrawalChecked` is always false here: a pack is a snapshot, and whether the signer has since withdrawn the record is a question for the log (findRecords).
 */
export async function verifyFile(bytes, trust, opts = {}) {
  const found = readEmbedded(bytes);
  if (!found) return { ok: false, embedded: false, why: "this file carries no proof" };
  if (found.damaged) return { ok: false, embedded: true, why: found.damaged };
  const claim = found.pack?.entry?.claim;
  if (found.pack?.entry?.t !== "record" || !claim) return { ok: false, embedded: true, why: "the proof is not for a record" };
  if (hex(sha256(found.original)) !== claim.sha256) return { ok: false, embedded: true, why: "this proof describes a different file" };
  const out = await verifyPack(found.pack, trust, opts);
  if (!out.ok) return { ...out, embedded: true };
  return { ...out, embedded: true, format: found.format, claim, withdrawalChecked: false };
}
