# @333eco/origin-verify

Checks a **B-Origin℠** record with no help from anyone: not from **HeartBank®**, not from a lookup service, and, with a saved pack, not from the network. No runtime dependencies. Runs in a browser or in Node.

A record is an entry in a public, append-only log at `log.333.eco`, made when a person signs a file with their passkey on `sign.333.eco`.

```sh
npx @333eco/origin-verify file picture.png    # finds the file's records by what it still is, and checks each one
npx @333eco/origin-verify record 0            # one record: signature, place in the tree, witnesses, clocks, Bitcoin
npx @333eco/origin-verify pack 0 record.json  # saves a pack
npx @333eco/origin-verify check record.json   # checks it, reading no network
npx @333eco/origin-verify audit               # the whole log, recomputed from its public tiles
```

```js
import { verifyPack, findRecords, hashFile } from "@333eco/origin-verify";
import trust from "@333eco/origin-verify/trust";

const result = await verifyPack(pack, trust);
```

## What a result means

Four states. Each stands alone and none implies another.

| state | it says | it rests on |
|---|---|---|
| `included` | this record is in the tree this checkpoint signs, and the log cannot later remove it unnoticed | the operator's keys and the Merkle proof |
| `witnessed` | enough outside witnesses cosigned the checkpoint | their signatures. ⚠️ False today: the log is on the Witness Network's testing list, not yet staging. Testing witnesses may cosign and `witnesses` names them, but they are not counted, because they may reset or disappear |
| `timestamped` | a checkpoint holding this record existed by this time | each authority's word, one per token |
| `bitcoin` | a checkpoint holding this record existed by this block | Bitcoin's proof of work |

**What a record does not say:** who imagined the work, or that one person holds one account. Without a signer's reveal it says *the operator witnessed this claim at this time and cannot later remove it*. With the reveal, *a passkey whose public key is given here signed exactly this claim*.

## Finding a file after its metadata is gone

| field | what it is | survives |
|---|---|---|
| `sha256` | the exact bytes | nothing changing the file |
| `pixels` | SHA-256 of the decoded picture as RGB, alpha dropped; PNG only, decoded here byte for byte | stripping metadata, re-compressing a PNG |
| `phash` | 64 bits: over white, luma, an exact box filter to 8×8, each cell above the mean or not | JPEG, scaling. A hint that two pictures look alike, nothing more |

`findRecords` reads the public log directly, so nobody learns what you checked. JPEG and other decoders differ, so those files never get `pixels`.

⚠️ The DCT hash most people reach for fails on pixel art: half the coefficients of a mirror-symmetric sprite are near zero, so their bits are noise. Measured on 150 pictures × 5 re-encodings, 40 of them symmetric sprites: this hash finds 99.7% of the same picture within distance 8, with 0.8% of different pictures within 8.

## Honest limits

- `trust.mjs` pins the log's keys and the timestamp authorities' roots. If you got this package from somewhere you don't trust, nothing here helps. npm provenance links each version to this repository's source.
- A timestamp token's certificate is judged at the token's own time. Revocation isn't checked: that would need the network and the authority's cooperation.
- A Bitcoin header proves its own work, but its height is the word of whoever supplied it. The CLI asks blockstream.info; check against your own node if it matters.
- It verifies. It never grades a person or a work, and it has no opinion on whether something is genuine.

CC0.
