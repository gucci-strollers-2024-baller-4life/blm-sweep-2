# Guntis Vitolins MetaMask 8.6 ETH — shard queue state (2026-11-12)

Target: `0x9c2f44efad0c1e852a09df9939e6daf061140caf`
Balance re-verified 2026-11-12 via blockscout: 8,612,541,554,265,619,929 wei (8.6126 ETH), unspent.

Repo name is historical: `blm-sweep-2` holds the **Guntis** sweep, not the BLM one. The BLM
queue is in `blm-sweep`.

## Shape of the space this queue covers

Fixed by the source material: `dutch` at slot 1, `fog` at slot 5, `parrot` at slot 12.
Free slots 1, 2, 3, 5, 6, 7, 8, 9, 10 (0-based positions inside the 12-word phrase) are filled
by every ordering of a 9-word candidate set.

Candidate sets are built in four tiers over `BASE = [atom, link, lake, song]`,
`COIN = [basic, token, dash]` and `POOL7 = [cattle, forest, wood, rib, roast, dinner, fresh]`:

- A: basic + token present, dash absent
- B: exactly one of basic/token, dash absent
- C: dash present, neither basic nor token
- D: everything else (34 four-word subsets in total across A-D)

Each subset is prefixed by `fiber fork round` + two words from POOL7 (21 pairs), giving
714 combinations, times 9! = 362,880 orderings = 259,096,320 raw phrases. BIP39 checksum
keeps roughly 1 in 16, so about 16.2M actual derivations.

Derivation: `m/44'/60'/0'/0/0` (MetaMask default), secp256k1 -> keccak256 -> last 20 bytes.
Checksum test is done on the 11-bit index packing before any key derivation, which is what
makes the throughput usable.

## Running it

- Local: `SHARD=s NSHARD=n python3 coin2.py` shards by `i % nshard` over the 714 combos,
  four worker processes inside each shard.
- Cloud: `.github/workflows/coin2x.yml` launches job 1 (`coin2` tier A-D over the 21 pairs)
  and job 2 (`coin3`, the second set) as 2 x 9 shards of `NSHARD=18` on GitHub-hosted runners.
  Public repo exists so Actions minutes are unmetered.
- Throughput measured locally: about 3,900 pairs/s per core for `coin2`-class spaces.
- Checkpoint discipline: GitHub runners are ephemeral, so a shard either finishes inside its
  180-minute timeout or restarts from zero. Size `NSHARD` so one shard is well under that.

## Status, stated honestly

- The local shard code is certified: checksum packing matches the reference, and the ETH
  derivation reproduces MetaMask's own address for a known mnemonic.
- No completed full-run log for the 714-combination space is in this repository. Do not treat
  this space as closed on the strength of a partial run.
- Standing policy for ETH prizes: **never auto-sweep**. On a match, hand the 12 words to the
  human; the human sweeps and announces.

## Word-pool correction (2026-10-23)

`free` is not a BIP39 word (checked against `bip39_english.txt`), so it was dropped from the
candidate pool and the `T3/free` tier is dead. Remaining unswept words worth keeping in the
pool: `memory`, `limit`, `core`, `power`, `possible`. `dutch` is verbatim in planted sentence
A1 ("Round dutch cattle...") and is the only Netherlands-candidate BIP39 word in any source
text, which is why it is fixed at slot 1.
