// Known answers from outside this package wherever they exist: NIST and RFC 8032 vectors, real RFC 3161 tokens and OpenTimestamps proofs from log.333.eco,
// real Bitcoin headers, PIL's reading of real PNGs. Every check also has a control that must fail.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import trust from "../trust.mjs";
import { b64, der, ed25519, ed25519ByHand, hex, hmacSha256, kids, sha256, unhex, utf8 } from "../primitives.mjs";
import { auditLog, checkCheckpoint, checkConsistency, checkOts, checkTimestamp, consistencyFor, decodePng, findRecords, hashFile, hashLeaf, packRecord, phashDistance, phashOf, proofFor, treeRoot, verifyPack, checkInclusion, canonical } from "../index.mjs";

const fx = (n) => readFileSync(new URL(`./fixtures/${n}`, import.meta.url));
const flip = (b, at = b.length >> 1) => { const c = Uint8Array.from(b); c[at] ^= 1; return c; };

test("KNOWN ANSWER: SHA-256 from NIST, and random lengths against Node's", () => {
    assert.equal(hex(sha256(utf8("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert.equal(hex(sha256(new Uint8Array(0))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert.equal(hex(sha256(utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    for (const n of [55, 56, 57, 63, 64, 65, 119, 120, 1000, 65536, 123457]) { const m = randomBytes(n); assert.equal(hex(sha256(m)), createHash("sha256").update(m).digest("hex"), `length ${n}`); }
});
test("HMAC-SHA256 against Node's", () => {
    for (const k of [1, 32, 64, 65, 200]) { const key = randomBytes(k), m = randomBytes(100); assert.equal(hex(hmacSha256(key, m)), createHmac("sha256", key).update(m).digest("hex")); }
});
test("KNOWN ANSWER: Ed25519 by hand on RFC 8032's vectors; a forgery, a high S and a bad key all fail", async () => {
    const pub = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"), sig = unhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    assert.equal(await ed25519ByHand(pub, unhex("72"), sig), true);
    assert.equal(await ed25519ByHand(pub, unhex("73"), sig), false);
    assert.equal(await ed25519ByHand(flip(pub, 3), unhex("72"), sig), false);
    assert.equal(await ed25519ByHand(pub, unhex("72"), flip(sig, 3)), false);
    const high = Uint8Array.from(sig); high.fill(0xff, 32); assert.equal(await ed25519ByHand(pub, unhex("72"), high), false, "S above the group order");
    assert.equal(await ed25519ByHand(pub, unhex("72"), sig.subarray(0, 63)), false);
    const L = 2n ** 252n + 27742317777372353535851937790883648493n; let S = 0n; for (let i = 63; i >= 32; i--) S = (S << 8n) + BigInt(sig[i]);
    const malleated = Uint8Array.from(sig); let m = S + L; for (let i = 32; i < 64; i++) { malleated[i] = Number(m & 255n); m >>= 8n; }
    assert.equal(await ed25519ByHand(pub, unhex("72"), malleated), false, "the same signature, plus the group order");
});
test("Ed25519 by hand agrees with WebCrypto and with Node over random keys", async () => {
    for (let i = 0; i < 8; i++) {
        const { publicKey, privateKey } = generateKeyPairSync("ed25519"), pub = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)), m = randomBytes(40), s = new Uint8Array(nodeSign(null, m, privateKey));
        assert.equal(await ed25519ByHand(pub, m, s), true);
        assert.equal(await ed25519(pub, m, s), true);
        assert.equal(await ed25519ByHand(pub, flip(m), s), false);
        assert.equal(await ed25519(pub, flip(m), s), false);
    }
});

const cpNote = fx("checkpoint").toString(), body = cpNote.slice(0, cpNote.indexOf("\n\n") + 1);
test("KNOWN ANSWER: the real checkpoint at size 1 verifies under the published key; another key and a changed root do not", async () => {
    const c = await checkCheckpoint(cpNote, trust);
    assert.equal(c.ok, true); assert.equal(c.size, 1);
    assert.equal((await checkCheckpoint(cpNote.replace("IVhe", "IVhf"), trust)).ok, false);
    assert.equal((await checkCheckpoint(cpNote, { ...trust, logVkey: "log.333.eco/origin+f3d66572+AXi0v2hiHpHIJ+jLtTsRr8Oy0xQsAOONP3DTlQIPd7QF".replace("AXi0", "AXi1") }).catch(() => ({ ok: false }))).ok, false);
});
test("KNOWN ANSWER: real record 0 audits from its real tile", async () => {
    const entry = fx("tile_entries_000.p_1");
    const leaf = hashLeaf(new Uint8Array(entry.subarray(2)));
    const cp = await checkCheckpoint(cpNote, trust);
    assert.deepEqual([...leaf], [...cp.root], "a tree of one is its leaf");
    const e = JSON.parse(entry.subarray(2).toString());
    assert.equal(canonical(e), entry.subarray(2).toString());
    const { checkWitnessSignature } = await import("../index.mjs");
    assert.equal(await checkWitnessSignature(e, trust), true);
    assert.equal(await checkWitnessSignature({ ...e, witnessedAt: "2020-01-01T00:00Z" }, trust), false);
});

for (const name of ["aped-gr", "accv-es", "freetsa-de"]) {
    test(`KNOWN ANSWER: ${name}'s real token verifies to its pinned root, at the time openssl reads`, async () => {
        const r = await checkTimestamp(new Uint8Array(fx(`stamps_1.${name}.tsr`)), utf8(body), trust.tsaRoots[name].map(b64));
        assert.equal(r.ok, true, r.why);
        assert.ok(r.time.startsWith("2026-11-03T16:"), r.time);
    });
    test(`CONTROLS ${name}: other data, another authority's root, and a flipped byte all fail`, async () => {
        const tok = new Uint8Array(fx(`stamps_1.${name}.tsr`)), roots = trust.tsaRoots[name].map(b64);
        assert.match((await checkTimestamp(tok, utf8(body + "x"), roots)).why, /different data/);
        const other = Object.keys(trust.tsaRoots).find((n) => n !== name);
        assert.match((await checkTimestamp(tok, utf8(body), trust.tsaRoots[other].map(b64))).why, /pinned root/);
        assert.equal((await checkTimestamp(tok, utf8(body), [])).ok, false, "no roots, no trust");
        // Everything that carries meaning is signed: the token's contents, its signed attributes, the signature, the signer's certificate. A flip anywhere in those must fail.
        const at = (n) => n.raw.byteOffset - tok.byteOffset;
        const signed = kids(kids(kids(der(tok))[1])[1].value.length ? kids(kids(der(tok))[1])[1] : der(tok))[0];
        const sd = kids(signed), encap = kids(sd[2]), si = kids(kids(sd[sd.length - 1])[0]), attrs = si.find((n) => n.tag === 0xa0);
        const certs = kids(sd.find((n) => n.tag === 0xa0)), issuerAndSerial = si[1];
        const leaf = certs.find((c) => { const t = kids(kids(c)[0]); const i = t[0].tag === 0xa0 ? 1 : 0; return Buffer.compare(t[i].value, kids(issuerAndSerial)[1]?.value ?? new Uint8Array(0)) === 0; });
        assert.ok(leaf, "this token names its signer by issuer and serial");
        const regions = { contents: encap[1], attrs, signature: si[si.indexOf(attrs) + 2], signerCert: leaf };
        const passed = [];
        for (const [name, n] of Object.entries(regions)) {
            const len = n.raw.length, stride = Math.max(1, Math.floor(len / 40));
            for (let o = at(n) + 4; o < at(n) + len; o += stride) if ((await checkTimestamp(flip(tok, o), utf8(body), roots)).ok) passed.push(`${name}@${o}`);
        }
        assert.deepEqual(passed, [], "no flip in a signed part passes");
        assert.equal((await checkTimestamp(flip(tok, 0), utf8(body), roots)).ok, false, "the outer tag");
    });
}
test("a token refused by the authority says so", async () => {
    const refused = unhex("3003" + "0201" + "02".padStart(2, "0")); // an impossible short form must not read as granted
    assert.equal((await checkTimestamp(refused, utf8(body), [])).ok, false);
});

const forged = (n) => new Uint8Array(fx(`tsa/${n}.tsr`)), forgedRoot = [new Uint8Array(fx("tsa/root.der"))], forgedData = new Uint8Array(fx("tsa/data.txt"));
test("CONTROLS on a chain no real authority would make (a throwaway CA): the good token passes, and each flaw fails for its own reason", async () => {
    const good = await checkTimestamp(forged("good"), forgedData, forgedRoot);
    assert.equal(good.ok, true, good.why);
    assert.equal(good.time, "2026-11-03T12:00:00.000Z");
    assert.match((await checkTimestamp(forged("no-eku"), forgedData, forgedRoot)).why, /not for time stamping/);
    assert.match((await checkTimestamp(forged("expired-leaf"), forgedData, forgedRoot)).why, /not valid at the token's time/);
    assert.match((await checkTimestamp(forged("under-non-ca"), forgedData, forgedRoot)).why, /does not reach a pinned root/, "a certificate that is no CA cannot vouch for another");
});

const header = (h) => unhex(fx(`header-${h}.hex`).toString().trim());
const body0 = (() => { const n = fx("checkpoints_0").toString(); return n.slice(0, n.indexOf("\n\n") + 1); })();
test("KNOWN ANSWER: the real genesis proof reaches real Bitcoin blocks, each header holding the proof's own result", async () => {
    const r = await checkOts(new Uint8Array(fx("stamps_0.ots")), sha256(utf8(body0)), { header: async (h) => header(h) });
    assert.equal(r.ok, true, r.why);
    const heights = [...new Set(r.bitcoin.map((a) => a.height))].sort();
    assert.deepEqual(heights, [974381, 974389]);
    assert.ok(r.bitcoin.every((a) => a.verified === true));
    assert.ok(r.bitcoin[0].time.startsWith("2026-11"), r.bitcoin[0].time);
});
test("OTS CONTROLS: other data, the wrong block, a header with no work, and an unknown operation", async () => {
    const proof = new Uint8Array(fx("stamps_0.ots")), d = sha256(utf8(body0));
    assert.match((await checkOts(proof, sha256(utf8("other")), {})).why, /different data/);
    const wrong = await checkOts(proof, d, { header: async (h) => header(h === 974381 ? 974389 : 974381) });
    assert.ok(wrong.bitcoin.every((a) => a.verified === false), "another block's root does not fit");
    const real = await checkOts(proof, d, { header: async (h) => header(h) });
    assert.ok(real.bitcoin.some((a) => a.verified === true), "the real headers fit, so what follows means something");
    const noWork = (h) => { const x = header(h); x[76] ^= 1; return x; };
    assert.ok((await checkOts(proof, d, { header: async (h) => noWork(h) })).bitcoin.every((a) => a.verified === false), "the right root in a header with no work behind it");
    const easy = (h) => { const x = header(h); x.set([0xff, 0xff, 0x7f, 0x22], 72); return x; };
    assert.ok((await checkOts(proof, d, { header: async (h) => easy(h) })).bitcoin.every((a) => a.verified === false), "a header that claims an impossibly easy target");
    const none = await checkOts(proof, d, {});
    assert.ok(none.bitcoin.every((a) => a.verified === null), "no header is not a verification");
    assert.equal((await checkOts(flip(proof, 3), d, {})).ok, false);
    assert.equal((await checkOts(proof.subarray(0, proof.length - 2), d, {})).ok, false, "truncated");
});

const expected = JSON.parse(fx("png/expected.json"));
for (const [name, want] of Object.entries(expected)) {
    test(`KNOWN ANSWER: ${name} (PIL mode ${want.mode}) hashes to PIL's own pixels`, async () => {
        const f = fx(`png/${name}.png`), h = await hashFile(f);
        assert.equal(h.sha256, createHash("sha256").update(f).digest("hex"));
        assert.equal(h.pixels, want.pixels);
        assert.match(h.phash, /^[0-9a-f]{16}$/);
    });
}
test("the record survives what strippers and re-encoders do: same pixels, different bytes", async () => {
    const a = await hashFile(fx("png/stripped-a.png")), b = await hashFile(fx("png/stripped-b.png"));
    assert.notEqual(a.sha256, b.sha256, "the bytes differ");
    assert.equal(a.pixels, b.pixels, "the picture does not");
    const c = await hashFile(fx("png/interlaced.png"));
    assert.equal(c.pixels, a.pixels, "interlacing is only an order of bytes");
    assert.equal(c.phash, a.phash);
});
test("phash holds through scaling and lossy re-encoding, and tells different pictures apart", async () => {
    const art = await decodePng(new Uint8Array(fx("png/art.png"))), base = phashOf(art);
    for (const [n, limit] of [["art-x4", 2], ["art-jpeg-round-trip", 8], ["art-half", 8]]) {
        const d = phashDistance(base, phashOf(await decodePng(new Uint8Array(fx(`png/${n}.png`)))));
        assert.ok(d <= limit, `${n}: distance ${d}`);
    }
    const other = phashDistance(base, phashOf(await decodePng(new Uint8Array(fx("png/rgb8.png")))));
    assert.ok(other >= 12, `a different picture: distance ${other}`);
});
test("REGRESSION: a mirror-symmetric sprite stays itself through a JPEG, which the DCT hash it replaced did not (its bits were noise)", async () => {
    const base = phashOf(await decodePng(new Uint8Array(fx("png/sym.png"))));
    for (const n of ["sym-q75", "sym-q50"]) { const d = phashDistance(base, phashOf(await decodePng(new Uint8Array(fx(`png/${n}.png`))))); assert.ok(d <= 8, `${n}: distance ${d}`); }
    assert.ok(phashDistance(base, phashOf(await decodePng(new Uint8Array(fx("png/sym-other.png"))))) >= 12, "CONTROL: another sprite is not near");
});
test("KNOWN ANSWER: the phash specification, worked by hand on a picture whose answer is obvious", () => {
    const w = 16, h = 16, rgb = new Uint8Array(w * h * 3).fill(255);
    for (let y = 0; y < h; y++) for (let x = 0; x < w / 2; x++) rgb.fill(0, (y * w + x) * 3, (y * w + x) * 3 + 3);
    assert.equal(phashOf({ width: w, height: h, rgb, alpha: null }), "0f0f0f0f0f0f0f0f", "left half black, right half white: the right four bits of every row");
    const top = new Uint8Array(w * h * 3).fill(255); top.fill(0, 0, (w * h * 3) / 2);
    assert.equal(phashOf({ width: w, height: h, rgb: top, alpha: null }), "00000000ffffffff", "top half black");
    assert.equal(phashOf({ width: 3, height: 3, rgb: new Uint8Array(27).fill(9), alpha: null }), "0000000000000000", "a flat picture has nothing above its mean");
});
test("phash is pure: the same pixels give the same 64 bits, and a transparent pixel reads as white", () => {
    const px = (w, h, f) => { const rgb = new Uint8Array(w * h * 3), alpha = new Uint8Array(w * h).fill(255); for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { const [r, g, b, a] = f(x, y); rgb.set([r, g, b], (y * w + x) * 3); alpha[y * w + x] = a; } return { width: w, height: h, rgb, alpha }; };
    const scene = (x, y) => (x < 20 && y > 10 ? [10, 20, 200, 255] : [250, 250, 250, 255]);
    const a = phashOf(px(64, 64, scene));
    assert.equal(a, phashOf(px(64, 64, scene)));
    const clear = phashOf(px(64, 64, (x, y) => (x < 20 && y > 10 ? [10, 20, 200, 255] : [0, 0, 0, 0])));
    assert.ok(phashDistance(a, clear) <= 2, "black under full transparency is not black");
});
test("a palette's transparency reaches the alpha channel, and a transparent pixel hashes as white", async () => {
    const p = await decodePng(new Uint8Array(fx("png/palette-trns.png")));
    assert.ok(p.alpha.some((a) => a === 0), "the transparent entry");
    assert.ok(p.alpha.some((a) => a === 255));
    const over = phashOf(p), ignored = phashOf({ ...p, alpha: null });
    assert.notEqual(over, ignored, "alpha changes the picture phash sees");
});
test("hashFile: a file that is no picture still has its bytes; a broken PNG has no picture; 16-bit gray is honest", async () => {
    const pdf = await hashFile(utf8("%PDF-1.7 not a picture"));
    assert.ok(pdf.sha256 && pdf.pixels === undefined && pdf.phash === undefined);
    const broken = Uint8Array.from(fx("png/rgb8.png")).subarray(0, 60);
    assert.equal((await hashFile(broken)).pixels, undefined);
    const gray16 = await hashFile(fx("png/gray16.png"));
    assert.equal(gray16.pixels, undefined, "PIL clips this mode, so no hash of ours could match it");
    const jpeg = await hashFile(fx("png/art-as.jpg"), { decode: async () => decodePng(new Uint8Array(fx("png/art.png"))) });
    assert.equal(jpeg.pixels, undefined, "⛔ a caller's decoder may give a phash, never pixels");
    assert.match(jpeg.phash, /^[0-9a-f]{16}$/);
});

// ── a whole log, built here with throwaway keys, for what the real one is too small to show ───────────────────────
function noteKey() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519"), raw = publicKey.export({ format: "der", type: "spki" }).subarray(12);
    const type = Buffer.from([1]), name = "test/log", id = createHash("sha256").update(`${name}\n`).update(type).update(raw).digest().subarray(0, 4);
    return { name, id, vkey: `${name}+${id.toString("hex")}+${Buffer.concat([type, raw]).toString("base64")}`, privateKey };
}
function p256() { const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { spki: publicKey.export({ format: "der", type: "spki" }).toString("base64"), privateKey }; }
function buildLog(claims, { nk = noteKey(), rk = p256() } = {}) {
    const t = { origin: "test/log", logVkey: nk.vkey, recordKeys: { k: rk.spki }, witnessQuorum: 2, witnesses: [], tsaRoots: {} };
    const sign = (e) => { const { witnessSig, ...rest } = e; const msg = Buffer.concat([Buffer.from(`b-origin/${e.t}/v${e.v}\0`), Buffer.from(canonical(rest))]); return { ...rest, witnessSig: nodeSign("sha256", msg, { key: rk.privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url") }; };
    const entries = claims.map((c, index) => (c.target !== undefined ? sign({ t: "withdraw", v: 1, index, target: c.target, kid: "k", witnessedAt: "2026-11-03T00:00Z" }) : sign({ t: "record", v: 2, index, claim: c, kid: "k", witnessedAt: "2026-11-03T00:00Z" })));
    const bytes = entries.map((e) => Buffer.from(canonical(e)));
    const noteAt = (n) => { const root = Buffer.from(treeRoot(bytes.slice(0, n).map((b) => hashLeaf(new Uint8Array(b))))).toString("base64"), b = `test/log\n${n}\n${root}\n`; return `${b}\n— test/log ${Buffer.concat([nk.id, nodeSign(null, Buffer.from(b), nk.privateKey)]).toString("base64")}\n`; };
    const files = new Map();
    const width = bytes.length % 256;
    const bundle = Buffer.concat(bytes.map((b) => { const l = Buffer.alloc(2); l.writeUInt16BE(b.length); return Buffer.concat([l, b]); }));
    files.set(`tile/entries/000${width ? `.p/${width}` : ""}`, bundle);
    files.set(`tile/0/000${width ? `.p/${width}` : ""}`, Buffer.concat(bytes.map((b) => Buffer.from(hashLeaf(new Uint8Array(b))))));
    files.set("checkpoint", Buffer.from(noteAt(bytes.length)));
    for (let n = 1; n <= bytes.length; n++) files.set(`checkpoints/${n}`, Buffer.from(noteAt(n)));
    return { t, files, get: async (p) => files.get(p) ?? null, noteAt, entries, nk, rk };
}
const claim = (s, extra = {}) => ({ v: 2, sha256: createHash("sha256").update(s).digest("hex"), mime: "image/png", bytes: 1, source: "digitalCreation", tool: "my-editor", declared: false, ...extra });

test("consistency proofs: every prefix of a tree checks, and a different history does not", () => {
    const leaves = Array.from({ length: 13 }, (_, i) => hashLeaf(utf8(`e${i}`)));
    for (let m = 0; m <= 13; m++) assert.ok(checkConsistency(m, 13, consistencyFor(leaves, m), treeRoot(leaves.slice(0, m)), treeRoot(leaves)), `prefix ${m}`);
    const other = [...leaves]; other[2] = hashLeaf(utf8("changed"));
    for (const m of [3, 4, 5, 8]) assert.equal(checkConsistency(m, 13, consistencyFor(other, m), treeRoot(leaves.slice(0, m)), treeRoot(other)), false, `rewritten before ${m}`);
    for (let i = 0; i < 13; i++) assert.ok(checkInclusion(leaves[i], i, 13, proofFor(leaves, i), treeRoot(leaves)));
});
test("findRecords: exact bytes, same pixels, near pictures and a withdrawal, each named; nothing else matches", async () => {
    const a = claim("a", { pixels: "a".repeat(64), phash: "00000000000000ff" }), b = claim("b", { pixels: "b".repeat(64), phash: "ff00000000000000" });
    const w = buildLog([a, b, { target: 0 }]);
    const size = 3;
    const exact = await findRecords(w.get, size, { sha256: a.sha256 });
    assert.deepEqual(exact.map((m) => [m.index, m.how, Boolean(m.withdrawnAt)]), [[0, "exact", true]]);
    assert.deepEqual((await findRecords(w.get, size, { sha256: "0".repeat(64), pixels: b.pixels })).map((m) => [m.index, m.how]), [[1, "same pixels"]]);
    const near = await findRecords(w.get, size, { phash: "00000000000000f0" });
    assert.deepEqual(near.map((m) => [m.index, m.how, m.distance]), [[0, "similar", 4]]);
    assert.deepEqual(await findRecords(w.get, size, { sha256: "0".repeat(64), pixels: "c".repeat(64), phash: "0f0f0f0f0f0f0f0f" }), []);
});
test("a pack checks with no network; tampering anywhere in it fails; each state stands alone", async () => {
    const w = buildLog([claim("a"), claim("b"), claim("c"), claim("d"), claim("e")]);
    const pack = await packRecord(w.get, 1, w.t);
    const r = await verifyPack(JSON.parse(JSON.stringify(pack)), w.t);
    assert.equal(r.ok, true, r.why);
    assert.equal(r.included, true); assert.equal(r.witnessed, false, "no cosignature is not a pass");
    assert.deepEqual(r.timestamped, []); assert.deepEqual(r.bitcoin, []);
    assert.match(r.conclusion, /operator witnessed/);
    for (const edit of [(p) => { p.entry.claim.sha256 = "0".repeat(64); }, (p) => { p.inclusion[0] = Buffer.alloc(32).toString("base64"); }, (p) => { p.checkpoint = w.noteAt(4); }, (p) => { p.kind = "other"; }]) {
        const c = JSON.parse(JSON.stringify(pack)); edit(c);
        assert.equal((await verifyPack(c, w.t)).ok, false, edit.toString());
    }
    await assert.rejects(packRecord(w.get, 9, w.t), /not yet in the tree/);
});
test("a stamp on an EARLIER checkpoint is only counted if that checkpoint held the record and the log extends it", async () => {
    const w = buildLog([claim("a"), claim("b"), claim("c"), claim("d")]);
    w.files.set("stamps/index.json", Buffer.from(JSON.stringify({ tsa: [1, 3], ots: [] })));
    const pack = await packRecord(w.get, 1, w.t);
    assert.equal(pack.stamps.tsa.size, 3, "the first stamp that held it, never one from before it joined");
    assert.equal((await verifyPack(pack, w.t)).ok, true);
    const before = JSON.parse(JSON.stringify(pack)); before.stamps.tsa.size = 1; before.stamps.tsa.checkpoint = w.noteAt(1); before.stamps.tsa.consistency = [];
    assert.match((await verifyPack(before, w.t)).why, /does not hold this record/);
    const fork = buildLog([claim("a"), claim("z"), claim("c"), claim("d")], { nk: w.nk, rk: w.rk });
    const split = JSON.parse(JSON.stringify(pack)); split.stamps.tsa.checkpoint = fork.noteAt(3);
    assert.equal((await checkCheckpoint(fork.noteAt(3), w.t)).ok, true, "the log's own key signed this other history: a split view");
    assert.match((await verifyPack(split, w.t)).why, /not a prefix/, "and it cannot lend its stamp to this one");
});
test("a token that fails is named as failing and never counted; a Bitcoin line that fails fails the pack; no header is reported as unchecked", async () => {
    const w = buildLog([claim("a"), claim("b")]);
    const note = w.noteAt(2), body2 = note.slice(0, note.indexOf("\n\n") + 1), digest = sha256(utf8(body2));
    const attest = Buffer.concat([Buffer.from([0x00]), Buffer.from("0588960d73d71901", "hex"), Buffer.from([3, 0xad, 0xbc, 0x3b])]);
    const magic = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
    const ots = Buffer.concat([magic, Buffer.from([1, 8]), digest, attest]);
    const trust2 = { ...w.t, tsaRoots: { x: [] } };
    w.files.set("stamps/index.json", Buffer.from(JSON.stringify({ tsa: [2], ots: [2] })));
    w.files.set("stamps/2.x.tsr", Buffer.from("not a token"));
    w.files.set("stamps/2.ots", ots);
    const pack = await packRecord(w.get, 0, trust2);
    const r = await verifyPack(pack, trust2);
    assert.equal(r.ok, true, r.why);
    assert.deepEqual(r.timestamped, []);
    assert.equal(r.timestampFailures[0].authority, "x");
    assert.deepEqual(r.bitcoin, []); assert.deepEqual(r.bitcoinUnchecked, [974381], "a Bitcoin line with no header is not a verification");
    const wrong = await verifyPack(pack, trust2, { header: async () => header(974381) });
    assert.match(wrong.why, /does not commit/);
});
test("a PNG that inflates past what its header allows is refused, not unpacked: a small file must not take the machine down", async () => {
    const { deflateSync, crc32 } = await import("node:zlib");
    const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const t = Buffer.from(type); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])) >>> 0); return Buffer.concat([len, t, data, crc]); };
    const ihdr = (w, h) => { const b = Buffer.alloc(13); b.writeUInt32BE(w, 0); b.writeUInt32BE(h, 4); b[8] = 8; b[9] = 2; return b; };
    const png = (w, h, raw) => Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr(w, h)), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
    const good = png(4, 4, Buffer.alloc((4 * 3 + 1) * 4));
    assert.equal((await decodePng(new Uint8Array(good))).width, 4, "CONTROL: an honest one opens");
    const bomb = png(4, 4, Buffer.alloc(64 * 1024 * 1024));
    assert.ok(bomb.length < 200 * 1024, `the file is small: ${bomb.length} B`);
    await assert.rejects(decodePng(new Uint8Array(bomb)), /inflates past/);
    assert.equal((await hashFile(bomb)).pixels, undefined, "and a file can still be hashed by its bytes");
    await assert.rejects(decodePng(new Uint8Array(good), { maxPixels: 15 }), /will not open/, "a caller can set a lower limit");
});
test("the testing list: every published witness key parses, a cosignature is named, and without a quorum it never counts as witnessed", async () => {
    assert.equal(trust.witnessQuorum, undefined, "while on the testing list");
    assert.equal(trust.witnessLabel, "testing witnesses");
    assert.equal((await checkCheckpoint(cpNote, trust)).ok, true);
    assert.equal(new Set(trust.witnesses.map((v) => v.split("+")[0])).size, 8);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519"), raw = publicKey.export({ format: "der", type: "spki" }).subarray(12);
    const name = "test/witness", type = Buffer.from([4]), id = createHash("sha256").update(`${name}\n`).update(type).update(raw).digest().subarray(0, 4);
    const vkey = `${name}+${id.toString("hex")}+${Buffer.concat([type, raw]).toString("base64")}`;
    const w = buildLog([claim("a")]), note = w.files.get("checkpoint").toString(), body = note.slice(0, note.indexOf("\n\n") + 1), time = Buffer.alloc(8);
    time.writeBigUInt64BE(1000n);
    const sig = nodeSign(null, Buffer.from(`cosignature/v1\ntime 1000\n${body}`), privateKey);
    w.files.set("checkpoint", Buffer.from(`${note}— ${name} ${Buffer.concat([id, time, sig]).toString("base64")}\n`));
    const testing = { ...w.t, witnesses: [vkey], witnessLabel: "testing witnesses" };
    delete testing.witnessQuorum;
    const r = await verifyPack(await packRecord(w.get, 0, testing), testing);
    assert.equal(r.ok, true, r.why);
    assert.deepEqual(r.witnesses, [name], "the cosignature is seen and named");
    assert.equal(r.witnessed, false, "and not counted");
    const counted = { ...testing, witnessQuorum: 1 };
    assert.equal((await verifyPack(await packRecord(w.get, 0, counted), counted)).witnessed, true, "CONTROL: with a quorum the same cosignature does count");
});
