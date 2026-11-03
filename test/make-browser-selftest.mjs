// Builds a page that runs the verifier's real-data checks in whatever browser opens it. <main> fills only when every one passes, so /safari's and /android's "did it render" IS the result.
//   node test/make-browser-selftest.mjs <out-dir>     then: node .claude/skills/safari/run.mjs <out-parent>   (serves <out-parent>/dist)
import { mkdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { join } from "node:path";
const out = process.argv[2], here = new URL("./fixtures/", import.meta.url), pkg = new URL("../", import.meta.url);
mkdirSync(out, { recursive: true });
for (const f of ["index.mjs", "primitives.mjs", "clocks.mjs", "media.mjs", "trust.mjs"]) copyFileSync(new URL(f, pkg), join(out, f));
const b = (n) => readFileSync(new URL(n, here)).toString("base64");
const fx = { checkpoint: readFileSync(new URL("checkpoint", here), "utf8"), checkpoint0: readFileSync(new URL("checkpoints_0", here), "utf8"), tile: b("tile_entries_000.p_1"), ots: b("stamps_0.ots"),
  tsr: Object.fromEntries(["aped-gr", "accv-es", "freetsa-de"].map((n) => [n, b(`stamps_1.${n}.tsr`)])), h1: readFileSync(new URL("header-974381.hex", here), "utf8").trim(), h2: readFileSync(new URL("header-974389.hex", here), "utf8").trim(),
  expected: JSON.parse(readFileSync(new URL("png/expected.json", here), "utf8")), png: {}, jpg: b("png/art-as.jpg"), art: b("png/art.png") };
for (const n of Object.keys(fx.expected)) fx.png[n] = b(`png/${n}.png`);
writeFileSync(join(out, "fixtures.mjs"), `export default ${JSON.stringify(fx)};\n`);
writeFileSync(join(out, "index.html"), `<!doctype html><meta charset="utf-8"><title>origin-verify self-test</title><meta name="viewport" content="width=device-width,initial-scale=1"><main></main><script type="module" src="selftest.mjs"></script>\n`);
writeFileSync(join(out, "selftest.mjs"), `
import fx from "./fixtures.mjs"; import trust from "./trust.mjs";
import { b64, ed25519, ed25519ByHand, hex, sha256, unhex, utf8 } from "./primitives.mjs";
import { canonical, checkCheckpoint, checkOts, checkTimestamp, checkWitnessSignature, hashFile, hashLeaf, phashDistance } from "./index.mjs";
import { canvasDecoder } from "./media.mjs";
const results = [];
const t = async (name, fn) => { try { results.push([name, (await fn()) === true]); } catch (e) { results.push([name, false, e.message]); } };
const body = fx.checkpoint.slice(0, fx.checkpoint.indexOf("\\n\\n") + 1), body0 = fx.checkpoint0.slice(0, fx.checkpoint0.indexOf("\\n\\n") + 1);
const pub = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"), sig = unhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
await t("sha256", () => hex(sha256(utf8("abc"))) === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
await t("ed25519 by hand, good", () => ed25519ByHand(pub, unhex("72"), sig));
await t("ed25519 by hand, bad", async () => !(await ed25519ByHand(pub, unhex("73"), sig)));
await t("ed25519, whichever this browser has", () => ed25519(pub, unhex("72"), sig));
await t("the real checkpoint", async () => (await checkCheckpoint(fx.checkpoint, trust)).ok);
await t("record 0's witness signature", async () => { const e = JSON.parse(new TextDecoder().decode(b64(fx.tile).subarray(2))); return (await checkWitnessSignature(e, trust)) && hex(hashLeaf(b64(fx.tile).subarray(2))) === hex((await checkCheckpoint(fx.checkpoint, trust)).root); });
for (const n of Object.keys(fx.tsr)) {
  await t("token " + n, async () => { const r = await checkTimestamp(b64(fx.tsr[n]), utf8(body), trust.tsaRoots[n].map(b64)); if (!r.ok) throw new Error(r.why); return true; });
  await t("token " + n + " refuses other data", async () => !(await checkTimestamp(b64(fx.tsr[n]), utf8(body + "x"), trust.tsaRoots[n].map(b64))).ok);
}
await t("the Bitcoin proof", async () => { const r = await checkOts(b64(fx.ots), sha256(utf8(body0)), { header: async (h) => unhex(h === 974381 ? fx.h1 : fx.h2) }); return r.ok && r.bitcoin.length > 0 && r.bitcoin.every((a) => a.verified === true); });
for (const [n, want] of Object.entries(fx.expected)) await t("pixels " + n, async () => (await hashFile(b64(fx.png[n]))).pixels === want.pixels);
await t("a browser's own decoder finds the JPEG near its original", async () => { const a = await hashFile(b64(fx.art)), j = await hashFile(b64(fx.jpg), { decode: (x) => canvasDecoder(x, "image/jpeg") }); return j.pixels === undefined && phashDistance(a.phash, j.phash) <= 8; });
const bad = results.filter((r) => !r[1]);
if (bad.length) { console.error("SELFTEST FAILED: " + JSON.stringify(bad)); throw new Error("SELFTEST FAILED: " + bad.map((b) => b[0] + (b[2] ? " (" + b[2] + ")" : "")).join("; ")); }
document.querySelector("main").textContent = "PASS " + results.length + " of " + results.length + " checks. " + navigator.userAgent;
`);
console.log("wrote", out);
