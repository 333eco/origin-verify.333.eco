// Version-3 records: a record names its PRESS, inside the log's signature, and a revealed press must carry the origin that press
// allows. A press made in the B-PoH app's own screen (press.shown = "app") carries an app origin the trust file lists; every other
// press carries sign.333.eco's — a passkey, every version-2 record, and an app key pressed through the phone's passkey sheet
// (shown = "site"), whose origin the BROWSER writes. A software key stands in for the app's here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import trust from "../trust.mjs";
import { checkReveal, canonical } from "../index.mjs";

const sha = (...p) => { const h = createHash("sha256"); for (const x of p) h.update(x); return h.digest(); };
const b64u = (b) => Buffer.from(b).toString("base64url");
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const lp = (b) => Buffer.concat([u32(b.length), b]);
const cbor = (pairs) => Buffer.concat([Buffer.from([0xa0 | pairs.length]), ...pairs.flatMap(([k, v]) => [
    Buffer.from([k >= 0 ? k : 0x20 | (-1 - k)]), Buffer.isBuffer(v) ? Buffer.concat([Buffer.from([0x58, v.length]), v]) : Buffer.from([v >= 0 ? v : 0x20 | (-1 - v)])])]);
const APP = "android:apk-key-hash:" + b64u(sha("the app's signing certificate"));
const TRUST = { ...trust, appOrigins: [APP] };

function pressed({ v = 3, press, origin }) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }), jwk = publicKey.export({ format: "jwk" });
    const claim = { v: 2, sha256: "ab".repeat(32), mime: "image/png", bytes: 1, source: "digitalCreation", tool: "sign.333.eco", declared: true };
    const nonce = randomBytes(32), salt = randomBytes(16);
    const claimCommitment = b64u(sha(Buffer.from("b-origin/claim/v1\0"), nonce, sha(Buffer.from(canonical(claim)))));
    const cose = cbor([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]);
    const auth = Buffer.concat([sha(Buffer.from(trust.rpId)), Buffer.from([0x05]), Buffer.alloc(4)]);
    const cd = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: claimCommitment, origin }));
    const sig = nodeSign("sha256", Buffer.concat([auth, sha(cd)]), privateKey);
    const assertionCommitment = b64u(sha(Buffer.from("b-origin/assertion/v1\0"), lp(salt), lp(auth), lp(cd), lp(sig), lp(cose)));
    const entry = { t: "record", v, claim, claimCommitment, assertionCommitment, ...(press ? { press } : {}) };
    const opening = { salt: b64u(salt), nonce: b64u(nonce), authenticatorData: b64u(auth), clientDataJSON: b64u(cd), signature: b64u(sig), credentialPublicKey: b64u(cose) };
    return { entry, opening };
}
const reveal = async (o, t = TRUST) => (await checkReveal(o.entry, o.opening, t)).ok;

test("CONTROL: a version-2 record pressed on sign.333.eco reveals as before", async () => {
    assert.equal(await reveal(pressed({ v: 2, origin: trust.webOrigin })), true);
});
test("a version-3 passkey press reveals with sign.333.eco's origin", async () => {
    assert.equal(await reveal(pressed({ press: { key: "passkey" }, origin: trust.webOrigin })), true);
});
test("a version-3 B-PoH app press reveals with an app origin the trust file lists", async () => {
    assert.equal(await reveal(pressed({ press: { key: "b-poh", unlock: "biometric", shown: "app" }, origin: APP })), true);
});
test("an app press is refused when the trust file lists no such app", async () => {
    assert.equal(await reveal(pressed({ press: { key: "b-poh", unlock: "pin", shown: "app" }, origin: APP }), trust), false);
});
test("neither can pose as the other: a passkey record with the app's origin, an app-screen record with the web origin, a v2 record with the app's", async () => {
    assert.equal(await reveal(pressed({ press: { key: "passkey" }, origin: APP })), false);
    assert.equal(await reveal(pressed({ press: { key: "b-poh", unlock: "biometric", shown: "app" }, origin: trust.webOrigin })), false);
    assert.equal(await reveal(pressed({ v: 2, origin: APP })), false);
});
test("an app key pressed through the phone's passkey sheet (shown: site) carries sign.333.eco's origin, which the browser writes", async () => {
    assert.equal(await reveal(pressed({ press: { key: "b-poh", unlock: "biometric", shown: "site" }, origin: trust.webOrigin })), true);
    assert.equal(await reveal(pressed({ press: { key: "b-poh", unlock: "biometric", shown: "site" }, origin: APP })), false);
});
test("CONTROL: a version-2 record cannot claim an app press, even naming one (the version clause)", async () => {
    assert.equal(await reveal(pressed({ v: 2, press: { key: "b-poh", unlock: "biometric", shown: "app" }, origin: APP })), false);
});
test("CONTROL: only a b-poh key may use an app origin, whatever else the press says", async () => {
    assert.equal(await reveal(pressed({ press: { key: "passkey", shown: "app" }, origin: APP })), false);
});
