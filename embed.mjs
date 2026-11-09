// Carries a record's pack inside the file it describes, so the file can be checked with nothing else (founder 2026-11-08).
// The pack goes in one removable place: a private PNG chunk, or JPEG APP9 segments. Taking it out gives back the signed bytes exactly, and that is
// how a reader knows the proof belongs to this file. The picture is never touched, so `pixels` and `phash` are the same with or without it.
// ⚠️ A pack is a snapshot: it cannot say the signer did not withdraw the record later. Only the log can (`withdrawalChecked: false` in verifyFile).
import { concat, hex, sha256, text, u32, utf8 } from "./primitives.mjs";

const MAX_PACK = 8 * 1024 * 1024;
const LABEL = utf8("b-origin-pack\0");
const PNG_SIG = [137, 80, 78, 71, 13, 10, 26, 10];
// Ancillary, private, and NOT safe to copy (the last letter is upper case): an editor that changes the image and does not know this chunk must drop it.
const PNG_TYPE = utf8("orGN");
const IEND = utf8("IEND");
const JPEG_DATA = 65533 - LABEL.length - 4; // an APP segment holds 65533 bytes after its length field

const CRC = Uint32Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = (...parts) => { let c = 0xffffffff; for (const p of parts) for (let i = 0; i < p.length; i++) c = CRC[(c ^ p[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const same = (b, at, want) => at + want.length <= b.length && want.every((x, i) => b[at + i] === x);
const u32At = (b, at) => new DataView(b.buffer, b.byteOffset + at, 4).getUint32(0);
const u16 = (n) => new Uint8Array([n >> 8, n & 255]);
const u16At = (b, at) => (b[at] << 8) | b[at + 1];
const isPng = (b) => same(b, 0, PNG_SIG);
const isJpeg = (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;

/** Where a PNG's chunks are, or why it can't be read. */
function pngChunks(b) {
  const out = [];
  for (let i = 8; i < b.length;) {
    if (i + 12 > b.length) return { why: "the PNG is cut short" };
    const n = u32At(b, i), end = i + 12 + n;
    if (end > b.length) return { why: "the PNG is cut short" };
    out.push({ at: i, end, type: b.subarray(i + 4, i + 8), data: b.subarray(i + 8, i + 8 + n), crc: u32At(b, i + 8 + n) });
    if (same(b, i + 4, IEND)) return { chunks: out };
    i = end;
  }
  return { why: "the PNG has no end" };
}
/** Our segments in a JPEG's header, in file order. Reads only up to the image data. */
function jpegOurs(b) {
  const ours = [];
  for (let i = 2; i + 2 <= b.length;) {
    if (b[i] !== 0xff) return { why: "the JPEG's header is damaged" };
    const m = b[i + 1];
    if (m === 0xff) { i++; continue; }
    if (m === 0xda || m === 0xd9) return { ours };
    if (m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
    if (i + 4 > b.length) return { why: "the JPEG's header is damaged" };
    const n = u16At(b, i + 2);
    if (n < 2 || i + 2 + n > b.length) return { why: "the JPEG's header is damaged" };
    if (m === 0xe9 && same(b, i + 4, LABEL)) ours.push({ at: i, end: i + 2 + n, seq: u16At(b, i + 4 + LABEL.length), total: u16At(b, i + 6 + LABEL.length), data: b.subarray(i + 8 + LABEL.length, i + 2 + n) });
    i += 2 + n;
  }
  return { why: "the JPEG's header is damaged" };
}
const without = (b, ranges) => { const parts = []; let at = 0; for (const r of ranges) { parts.push(b.subarray(at, r.at)); at = r.end; } parts.push(b.subarray(at)); return concat(...parts); };
function parsePack(raw) {
  if (raw.length > MAX_PACK) return { damaged: "the proof is too large" };
  try { return { pack: JSON.parse(text(raw)) }; } catch { return { damaged: "the proof can't be read" }; }
}

/**
 * The proof a file carries: null if none, { format, damaged } if it is broken, or { format, pack, original } where `original` is the file without it.
 * ⛔ This only reads. Nothing here says the proof is good, or that it belongs to this file: verifyFile does.
 */
export function readEmbedded(bytes) {
  const b = new Uint8Array(bytes);
  if (isPng(b)) {
    const { chunks, why } = pngChunks(b);
    if (why) return null;
    const ours = chunks.filter((c) => same(c.type, 0, PNG_TYPE));
    if (!ours.length) return null;
    if (ours.length > 1) return { format: "png", damaged: "the file carries more than one proof" };
    const [c] = ours;
    if (crc32(c.type, c.data) !== c.crc) return { format: "png", damaged: "the proof was changed" };
    if (!same(c.data, 0, LABEL)) return { format: "png", damaged: "the proof can't be read" };
    const p = parsePack(c.data.subarray(LABEL.length));
    return p.damaged ? { format: "png", ...p } : { format: "png", pack: p.pack, original: without(b, [c]) };
  }
  if (isJpeg(b)) {
    const { ours, why } = jpegOurs(b);
    if (why || !ours.length) return null;
    const total = ours[0].total;
    if (ours.length !== total || ours.some((s, i) => s.seq !== i || s.total !== total)) return { format: "jpeg", damaged: "part of the proof is missing" };
    const p = parsePack(concat(...ours.map((s) => s.data)));
    return p.damaged ? { format: "jpeg", ...p } : { format: "jpeg", pack: p.pack, original: without(b, ours) };
  }
  return null;
}

/**
 * A copy of the file with this pack inside. Refuses a pack for any other file. A proof already there is replaced, so a pack can be renewed as it gains its clocks.
 * A pack that holds an `opening` shows the passkey's public key to anyone with the file: every file that carries that opening's key can be linked to the others. That is the signer's choice to make.
 */
export function embedPack(bytes, pack) {
  if (pack?.kind !== "b-origin-pack" || pack.entry?.t !== "record") throw new TypeError("not a B-Origin pack for a record");
  const b = new Uint8Array(bytes), had = readEmbedded(b);
  if (had?.damaged) throw new Error(`can't renew: ${had.damaged}`);
  const base = had ? had.original : b;
  if (hex(sha256(base)) !== pack.entry.claim?.sha256) throw new Error("this pack describes a different file");
  const raw = utf8(JSON.stringify(pack));
  if (raw.length > MAX_PACK) throw new Error("the pack is too large to carry");
  if (isPng(base)) {
    const { chunks, why } = pngChunks(base);
    if (why) throw new Error(why);
    const end = chunks[chunks.length - 1], data = concat(LABEL, raw);
    return concat(base.subarray(0, end.at), u32(data.length), PNG_TYPE, data, u32(crc32(PNG_TYPE, data)), base.subarray(end.at));
  }
  if (isJpeg(base)) {
    const total = Math.ceil(raw.length / JPEG_DATA);
    if (total > 0xffff) throw new Error("the pack is too large to carry");
    const parts = [base.subarray(0, 2)];
    for (let i = 0; i < total; i++) {
      const data = raw.subarray(i * JPEG_DATA, (i + 1) * JPEG_DATA);
      parts.push(new Uint8Array([0xff, 0xe9]), u16(2 + LABEL.length + 4 + data.length), LABEL, u16(i), u16(total), data);
    }
    parts.push(base.subarray(2));
    return concat(...parts);
  }
  throw new Error("a proof can be carried only in a PNG or a JPEG: keep the pack beside any other file");
}
