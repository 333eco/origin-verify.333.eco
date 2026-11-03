#!/usr/bin/env node
// origin-verify file <path> [url]            finds a file's records by what it still is, and checks each one
// origin-verify record <index> [url]         one record: signature, place in the tree, witnesses, clocks, Bitcoin
// origin-verify pack <index> <out> [url]     saves a pack that checks offline, with no help from anyone
// origin-verify check <pack>                 checks a saved pack. Reads no network
// origin-verify proof <file> [url]           a signer's saved proof file, with its reveal
// origin-verify audit [url]                  the whole log, recomputed from its public tiles
import { readFileSync, writeFileSync } from "node:fs";
import trust from "./trust.mjs";
import { auditLog, checkCheckpoint, findRecords, hashFile, packRecord, readEntries, verifyPack } from "./index.mjs";

const [cmd, a, b, c] = process.argv.slice(2);
const baseOf = (u) => (u ?? "https://log.333.eco/origin/").replace(/\/?$/, "/");
const getter = (base) => async (path) => { const r = await fetch(base + path); if (r.status === 404) return null; if (!r.ok) throw new Error(`${path}: ${r.status}`); return new Uint8Array(await r.arrayBuffer()); };
const say = (o) => { console.log(JSON.stringify(o, null, 2)); process.exit(o.ok === false ? 1 : 0); };
/** One public source for block headers. Each header proves its own work, but the height is this source's word: compare with your own node if it matters. */
const header = async (height) => {
  const hash = await (await fetch(`https://blockstream.info/api/block-height/${height}`)).text();
  const hx = await (await fetch(`https://blockstream.info/api/block/${hash}/header`)).text();
  return Uint8Array.from(hx.match(/../g), (x) => parseInt(x, 16));
};
const latest = async (get) => new TextDecoder().decode(await get("checkpoint"));

if (cmd === "audit") { const get = getter(baseOf(a)); say(await auditLog(get, await latest(get), trust)); }
else if (cmd === "record") { const get = getter(baseOf(b)); say(await verifyPack(await packRecord(get, Number(a), trust, { header }), trust)); }
else if (cmd === "pack") { const get = getter(baseOf(c)); writeFileSync(b, JSON.stringify(await packRecord(get, Number(a), trust, { header }), null, 2)); console.log(`saved ${b}`); }
else if (cmd === "check") say(await verifyPack(JSON.parse(readFileSync(a, "utf8")), trust));
else if (cmd === "proof") { const get = getter(baseOf(b)), p = JSON.parse(readFileSync(a, "utf8")); say(await verifyPack(await packRecord(get, p.index, trust, { opening: p.opening, header }), trust)); }
else if (cmd === "file") {
  const get = getter(baseOf(b)), cp = await checkCheckpoint(await latest(get), trust);
  if (!cp.ok) say(cp);
  const hashes = await hashFile(readFileSync(a));
  const found = await findRecords(get, cp.size, hashes);
  const records = [];
  for (const m of found) records.push({ how: m.how, ...(m.distance !== undefined ? { distance: m.distance } : {}), ...(m.withdrawnAt ? { withdrawnAt: m.withdrawnAt } : {}), claim: m.entry.claim, ...(await verifyPack(await packRecord(get, m.index, trust, { header }), trust)) });
  say({ ok: true, hashes, logSize: cp.size, records });
} else { console.error("usage: origin-verify file|record|pack|check|proof|audit …"); process.exit(2); }
