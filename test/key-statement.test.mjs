// Key statements and revocations (b-poh-statements §5, §6.1): what a checker may say about the KEY behind a b-poh press, as of the press's
// minute. Every guard has a case that must fail. Software keys stand in for the key statement key and the passkeys.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import trust from "../trust.mjs";
import { canonical, checkKeyStatement, checkReveal, keyIdOf, revocationsIn } from "../index.mjs";

const sha = (...p) => { const h = createHash("sha256"); for (const x of p) h.update(x); return h.digest(); };
const b64u = (b) => Buffer.from(b).toString("base64url");
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const lp = (b) => Buffer.concat([u32(b.length), b]);
const cbor = (pairs) => Buffer.concat([Buffer.from([0xa0 | pairs.length]), ...pairs.flatMap(([k, v]) => [
    Buffer.from([k >= 0 ? k : 0x20 | (-1 - k)]), Buffer.isBuffer(v) ? Buffer.concat([Buffer.from([0x58, v.length]), v]) : Buffer.from([v >= 0 ? v : 0x20 | (-1 - v)])])]);
const p256 = () => { const k = generateKeyPairSync("ec", { namedCurve: "P-256" }); return { ...k, spki: k.publicKey.export({ format: "der", type: "spki" }).toString("base64") }; };
const signRaw = (key, msg) => b64u(nodeSign("sha256", msg, { key, dsaEncoding: "ieee-p1363" }));

const K12 = p256(), K1 = p256();
const TRUST = { ...trust, keyStatementKeys: { "k12-t": K12.spki }, recordKeys: { "k1-t": K1.spki } };
const COSE = randomBytes(77), KEY = keyIdOf(COSE);
const OPENING = { credentialPublicKey: b64u(COSE) };
const PRESS = { t: "record", v: 3, press: { key: "b-poh", unlock: "biometric", shown: "app" }, witnessedAt: "2026-11-26T10:00Z" };

function statement(over = {}, signer = K12.privateKey, kid = "k12-t") {
    const s = { t: "key", v: 1, key: KEY, checked: "2026-11-25T09:00Z",
        attested: { platform: "android", chip: "trusted-environment", unlock: "biometric", boot: "verified", locked: true, patch: "2026-01", app: "b-poh" },
        declared: { endsOnNewEnrollment: true, sensorsPresent: ["fingerprint", "face"] }, kid, ...over };
    s.sig = signRaw(signer, Buffer.concat([Buffer.from("b-origin/key/v1\0"), Buffer.from(canonical(s))]));
    return s;
}
function revoke(over = {}) { // a log entry as sign.333.eco writes it, witness-signed by the record key under its own label
    const e = { t: "revoke", v: 1, index: 40, keys: [KEY], compromised: "2026-11-25T18:00Z", by: "operator", witnessedAt: "2026-11-26T12:00Z", kid: "k1-t", ...over };
    e.witnessSig = signRaw(K1.privateKey, Buffer.concat([Buffer.from(`b-origin/${e.t}/v${e.v}\0`), Buffer.from(canonical(e))]));
    return e;
}

test("a key statement under the key statement key, for this press's key: covered when no revocation reaches the press", async () => {
    const r = await checkKeyStatement(statement(), PRESS, OPENING, TRUST, []);
    assert.equal(r.ok, true, r.why); assert.equal(r.covered, true);
    assert.deepEqual(r.declared, { endsOnNewEnrollment: true, sensorsPresent: ["fingerprint", "face"] }, "declared returned apart");
    assert.equal(r.attested.unlock, "biometric");
});

test("REFUSALS: another key's signature, a RECORD key's, a changed field, another press's key, a passkey record, another unlock, dated after the press", async () => {
    const no = async (s, entry = PRESS, opening = OPENING, t = TRUST) => (await checkKeyStatement(s, entry, opening, t, [])).ok;
    assert.equal(await no(statement({}, p256().privateKey)), false, "signed by a key the trust file doesn't list");
    assert.equal(await no(statement({}, K1.privateKey, "k1-t")), false, "a record key never signs a key statement (not in keyStatementKeys)");
    assert.equal(await no({ ...statement(), attested: { ...statement().attested, boot: "unverified" } }), false, "one attested field changed");
    assert.equal(await no(statement(), PRESS, { credentialPublicKey: b64u(randomBytes(77)) }), false, "another press's key");
    assert.equal(await no(statement(), { ...PRESS, press: { key: "passkey" } }), false, "a passkey record");
    assert.equal(await no(statement(), { ...PRESS, v: 2, press: undefined }), false, "a version-2 record");
    assert.equal(await no(statement(), { ...PRESS, press: { ...PRESS.press, unlock: "pin" } }), false, "a PIN press against a biometric key");
    assert.equal(await no(statement({ checked: "2026-11-26T10:01Z" })), false, "a statement dated after the press");
    assert.equal(await no({ ...statement(), t: "record" }), false, "not a key statement");
    assert.equal(await no(statement(), PRESS, OPENING, { ...TRUST, keyStatementKeys: undefined }), false, "no key statement keys trusted");
});

test("a revocation reaching back to the press un-covers it, with both dates; one after the press does not; an unread log is never covered", async () => {
    const st = statement();
    const before = await checkKeyStatement(st, PRESS, OPENING, TRUST, [revoke({ compromised: "2026-11-26T09:59Z" })]);
    assert.equal(before.ok, true); assert.equal(before.covered, false);
    assert.deepEqual(before.revoked, { compromised: "2026-11-26T09:59Z", known: "2026-11-26T12:00Z", by: "operator", index: 40 });
    const atTheMinute = await checkKeyStatement(st, PRESS, OPENING, TRUST, [revoke({ compromised: "2026-11-26T10:00Z" })]);
    assert.equal(atTheMinute.covered, false, "compromised AT the press's minute reaches it");
    assert.equal((await checkKeyStatement(st, PRESS, OPENING, TRUST, [revoke({ compromised: "2026-11-26T10:01Z" })])).covered, true, "after the press: still covered");
    assert.equal((await checkKeyStatement(st, PRESS, OPENING, TRUST, [revoke({ keys: [keyIdOf(randomBytes(77))] })])).covered, true, "another key's revocation");
    const unread = await checkKeyStatement(st, PRESS, OPENING, TRUST, null);
    assert.equal(unread.ok, true); assert.equal(unread.covered, null, "⛔ never read as covered"); assert.match(unread.why, /couldn't be checked/);
});

test("revocationsIn keeps only revoke entries the record key signed under their own label", async () => {
    const good = revoke(), { witnessSig: _w, ...unsigned } = revoke();
    const wrongLabel = { ...unsigned, witnessSig: signRaw(K1.privateKey, Buffer.concat([Buffer.from("b-origin/record/v1\0"), Buffer.from(canonical(unsigned))])) };
    const notOurs = revoke(); notOurs.witnessSig = signRaw(p256().privateKey, Buffer.from("x"));
    const out = await revocationsIn([{ t: "record", v: 3 }, good, wrongLabel, notOurs, { t: "void", v: 1, index: 3 }], TRUST);
    assert.deepEqual(out, [good]);
});

test("a HOLDER's revocation reveals like a record: one passkey press bound to every key, in order, and the date; an operator's has nothing to reveal", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }), jwk = publicKey.export({ format: "jwk" });
    const keys = [KEY, keyIdOf(randomBytes(77))], compromised = "2026-11-25T18:00Z", nonce = randomBytes(32), salt = randomBytes(16);
    const claimCommitment = b64u(sha(Buffer.from("b-origin/revoke/v1\0"), nonce, u32(keys.length), ...keys.map((k) => lp(Buffer.from(k, "base64url"))), lp(Buffer.from(compromised))));
    const cose = cbor([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]);
    const auth = Buffer.concat([sha(Buffer.from(trust.rpId)), Buffer.from([0x05]), Buffer.alloc(4)]);
    const cd = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: claimCommitment, origin: trust.webOrigin }));
    const sig = nodeSign("sha256", Buffer.concat([auth, sha(cd)]), privateKey);
    const assertionCommitment = b64u(sha(Buffer.from("b-origin/assertion/v1\0"), lp(salt), lp(auth), lp(cd), lp(sig), lp(cose)));
    const entry = { t: "revoke", v: 1, keys, compromised, by: "holder", claimCommitment, assertionCommitment };
    const opening = { salt: b64u(salt), nonce: b64u(nonce), authenticatorData: b64u(auth), clientDataJSON: b64u(cd), signature: b64u(sig), credentialPublicKey: b64u(cose) };
    assert.equal((await checkReveal(entry, opening, trust)).ok, true);
    assert.equal((await checkReveal({ ...entry, keys: [...keys].reverse() }, opening, trust)).ok, false, "CONTROL: the keys' order is bound");
    assert.equal((await checkReveal({ ...entry, keys: keys.slice(0, 1) }, opening, trust)).ok, false, "CONTROL: every key is bound");
    assert.equal((await checkReveal({ ...entry, compromised: "2026-11-21T00:00Z" }, opening, trust)).ok, false, "CONTROL: the date is bound");
    assert.equal((await checkReveal({ ...entry, by: "operator" }, opening, trust)).ok, false, "an operator's revocation has no press to reveal");
});
