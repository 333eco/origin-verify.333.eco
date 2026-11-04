// What a file still is after its metadata is gone. ⭐ `pixels` is /media's `ma:pixels`: SHA-256 of the decoded raster as RGB bytes, alpha dropped, and it must match PIL's
// `im.convert("RGB").tobytes()` exactly (test: real files against PIL). So PNG is decoded here, byte for byte: a browser's canvas premultiplies alpha and rounds.
// ⚠️ JPEG, WebP and the rest differ a little from decoder to decoder, so they get no `pixels`; `phash` still finds them. ⛔ Permanent once in the log: a change is a new field.
import { concat, hex, sha256 } from "./primitives.mjs";

const SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const MAX_PIXELS = 100_000_000;
export const isPng = (b) => SIG.every((x, i) => b[i] === x);

/** Stops at `limit`: a small file can inflate to gigabytes, and the header already says how big a real one can be. */
async function inflate(data, limit) {
  const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream("deflate")).getReader(), parts = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) { await reader.cancel().catch(() => {}); throw new Error("a PNG that inflates past what its header allows"); }
    parts.push(value);
  }
  return concat(...parts);
}
const ADAM7 = [[0, 0, 8, 8], [4, 0, 8, 8], [0, 4, 4, 8], [2, 0, 4, 4], [0, 2, 2, 4], [1, 0, 2, 2], [0, 1, 1, 2]];

/** Returns { width, height, rgb, alpha } as 8-bit rasters. `rgb` is null for 16-bit gray, which PIL clips rather than reduces, so no hash could match it. */
export async function decodePng(b, { maxPixels = MAX_PIXELS } = {}) {
  if (!isPng(b)) throw new Error("not a PNG");
  const dv = new DataView(b.buffer, b.byteOffset, b.length);
  let i = 8, width, height, depth, color, interlace, palette = null, trns = null;
  const idat = [];
  while (i + 8 <= b.length) {
    const len = dv.getUint32(i), type = String.fromCharCode(b[i + 4], b[i + 5], b[i + 6], b[i + 7]), data = b.subarray(i + 8, i + 8 + len);
    if (i + 12 + len > b.length) throw new Error("a truncated PNG");
    if (type === "IHDR") { width = dv.getUint32(i + 8); height = dv.getUint32(i + 12); depth = b[i + 16]; color = b[i + 17]; interlace = b[i + 20]; }
    else if (type === "PLTE") palette = data;
    else if (type === "tRNS") trns = data;
    else if (type === "IDAT") idat.push(data);
    else if (type === "IEND") break;
    i += 12 + len;
  }
  if (!width || !height || !idat.length || width * height > maxPixels) throw new Error("a PNG this reader will not open");
  const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[color];
  if (!channels || (color === 3 && !palette)) throw new Error("a PNG with an unknown color type");
  const bitsPerPixel = channels * depth, bpp = Math.max(1, bitsPerPixel >> 3);
  // The most a real image of this size can need; interlacing repeats a line's filter byte in up to seven passes, so a generous bound covers it.
  const raw = await inflate(concat(...idat), (Math.ceil((width * bitsPerPixel) / 8) + 1) * height * (interlace === 1 ? 2 : 1) + 1024);
  const rgb = new Uint8Array(width * height * 3), alpha = new Uint8Array(width * height).fill(255);
  let at = 0;
  const pass = (w, h, put) => {
    if (w === 0 || h === 0) return;
    const stride = Math.ceil((w * bitsPerPixel) / 8);
    let prev = new Uint8Array(stride);
    for (let y = 0; y < h; y++) {
      if (at + 1 + stride > raw.length) throw new Error("a truncated PNG");
      const filter = raw[at++], line = raw.slice(at, at + stride); at += stride;
      for (let x = 0; x < stride; x++) {
        const a = x >= bpp ? line[x - bpp] : 0, u = prev[x], c = x >= bpp ? prev[x - bpp] : 0;
        if (filter === 1) line[x] += a;
        else if (filter === 2) line[x] += u;
        else if (filter === 3) line[x] += (a + u) >> 1;
        else if (filter === 4) { const p = a + u - c, pa = Math.abs(p - a), pb = Math.abs(p - u), pc = Math.abs(p - c); line[x] += pa <= pb && pa <= pc ? a : pb <= pc ? u : c; }
        else if (filter !== 0) throw new Error("a PNG with an unknown filter");
      }
      for (let px = 0; px < w; px++) put(px, y, line);
      prev = line;
    }
  };
  const sample = (line, px, ch) => {
    if (depth === 8) return line[px * channels + ch];
    if (depth === 16) return line[(px * channels + ch) * 2]; // the high byte, as PIL keeps
    const bit = px * depth, v = (line[bit >> 3] >> (8 - depth - (bit & 7))) & ((1 << depth) - 1);
    return v;
  };
  const scale = depth < 8 && color === 0 ? 255 / ((1 << depth) - 1) : 1;
  const write = (X, Y, line, px) => {
    const o = Y * width, p = (o + X) * 3;
    if (color === 3) {
      const v = sample(line, px, 0);
      rgb[p] = palette[v * 3]; rgb[p + 1] = palette[v * 3 + 1]; rgb[p + 2] = palette[v * 3 + 2];
      if (trns && v < trns.length) alpha[o + X] = trns[v];
    } else if (color === 0 || color === 4) {
      const v = sample(line, px, 0) * scale;
      rgb[p] = rgb[p + 1] = rgb[p + 2] = v;
      if (color === 4) alpha[o + X] = sample(line, px, 1);
    } else {
      rgb[p] = sample(line, px, 0); rgb[p + 1] = sample(line, px, 1); rgb[p + 2] = sample(line, px, 2);
      if (color === 6) alpha[o + X] = sample(line, px, 3);
    }
  };
  if (interlace === 1) {
    for (const [x0, y0, dx, dy] of ADAM7) {
      const w = Math.ceil((width - x0) / dx), h = Math.ceil((height - y0) / dy);
      pass(w, h, (px, y, line) => write(x0 + px * dx, y0 + y * dy, line, px));
    }
  } else pass(width, height, (px, y, line) => write(px, y, line, px));
  return { width, height, rgb: depth === 16 && (color === 0 || color === 4) ? null : rgb, alpha };
}

// ── phash ─────────────────────────────────────────────────────────────────────────────────────────────────────────
// 64 bits, specified here because they enter a permanent log: over white → luma → an exact box filter to 8×8 → each cell above the mean of all 64 or not, row by row, high bit first.
// ⭐ Measured 2026-11-03, 150 pictures × 5 re-encodings, 40 of them mirror-symmetric sprites: this finds 99.7% of the same picture at distance ≤ 8 with 0.8% of different pictures near.
// ⛔ The DCT hash everyone reaches for fails exactly on pixel art: half the coefficients of a symmetric picture are near zero, so their bits are noise (median distance 14 from a JPEG of itself).
// It is a hint that two pictures look alike, nothing more: an unrelated flat picture can land near.
export function phashOf({ width, height, rgb, alpha }) {
  // 1000 × luma over white. Whole numbers and divisions only, so every engine agrees to the bit.
  const luma = (x, y) => {
    const p = (y * width + x) * 3, a = alpha ? alpha[y * width + x] : 255, over = (c) => c * a + 255 * (255 - a);
    return (299 * over(rgb[p]) + 587 * over(rgb[p + 1]) + 114 * over(rgb[p + 2])) / 255;
  };
  // Each cell covers W/8 × H/8 source pixels; overlaps are counted in eighths of a pixel, so the weights are whole numbers.
  const spans = (size) => { const out = []; for (let i = 0; i < 8; i++) { const lo = i * size, hi = (i + 1) * size, s = []; for (let p = Math.floor(lo / 8); p * 8 < hi; p++) s.push([p, Math.min(hi, (p + 1) * 8) - Math.max(lo, p * 8)]); out.push(s); } return out; };
  const xs = spans(width), ys = spans(height), cells = [];
  for (let j = 0; j < 8; j++) for (let i = 0; i < 8; i++) {
    let sum = 0;
    for (const [y, oy] of ys[j]) for (const [x, ox] of xs[i]) sum += luma(x, y) * ox * oy;
    cells.push(sum / (width * height));
  }
  const mean = cells.reduce((a, b) => a + b, 0) / 64, out = new Uint8Array(8);
  cells.forEach((c, i) => { if (c > mean) out[i >> 3] |= 0x80 >> (i & 7); });
  return hex(out);
}
export function phashDistance(a, b) {
  let d = 0;
  for (let i = 0; i < 16; i += 2) { let x = parseInt(a.slice(i, i + 2), 16) ^ parseInt(b.slice(i, i + 2), 16); while (x) { d += x & 1; x >>= 1; } }
  return d;
}

/**
 * A browser's own decoder, for the types this file does not decode. Good for `phash` and nothing stricter: Safari's private browsing adds noise to canvas reads on purpose,
 * and JPEG decoders differ, which a 64-bit hash of the shape shrugs off and an exact hash would not.
 */
export async function canvasDecoder(bytes, mime) {
  const blob = new Blob([bytes], mime ? { type: mime } : {});
  const bmp = await createImageBitmap(blob, { premultiplyAlpha: "none", colorSpaceConversion: "none" });
  const canvas = typeof OffscreenCanvas !== "undefined" ? new OffscreenCanvas(bmp.width, bmp.height) : Object.assign(document.createElement("canvas"), { width: bmp.width, height: bmp.height });
  const ctx = canvas.getContext("2d");
  ctx.drawImage(bmp, 0, 0);
  const { data, width, height } = ctx.getImageData(0, 0, bmp.width, bmp.height);
  const rgb = new Uint8Array(width * height * 3), alpha = new Uint8Array(width * height);
  for (let i = 0; i < width * height; i++) { rgb[i * 3] = data[i * 4]; rgb[i * 3 + 1] = data[i * 4 + 1]; rgb[i * 3 + 2] = data[i * 4 + 2]; alpha[i] = data[i * 4 + 3]; }
  bmp.close?.();
  return { width, height, rgb, alpha };
}

/**
 * The hashes a claim carries. `decode(bytes)` is the caller's own decoder for other image types, returning { width, height, rgb, alpha }: it may give `phash`, never `pixels`.
 * A file that is not a picture, or that nothing can decode, simply has neither: it can still be signed, and found only by its exact bytes.
 */
export async function hashFile(bytes, { decode, maxPixels } = {}) {
  const b = new Uint8Array(bytes);
  const sha = new Uint8Array(await crypto.subtle.digest("SHA-256", b));
  const out = { sha256: hex(sha), bytes: b.length };
  try {
    if (isPng(b)) {
      const png = await decodePng(b, maxPixels ? { maxPixels } : {});
      if (png.rgb) { out.pixels = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", png.rgb))); out.phash = phashOf(png); }
    } else if (decode) {
      const r = await decode(b);
      if (r) out.phash = phashOf(r);
    }
  } catch { /* what cannot be decoded has no picture to speak of */ }
  return out;
}
