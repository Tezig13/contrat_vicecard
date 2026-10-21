# VICECARDS vault (Solana program)

The on-chain vault of VICECARDS. The VICECARDS coin is created on pump.fun with this program's
`vault` PDA as its creator and TTWO as its quote, so every creator fee belongs to the vault, in TTWO.
Every hour the operator publishes the merkle root of each collector's cumulative entitlement
(`set_root`); the program refuses a root that commits more TTWO than the vault holds. Anyone can
then pay a wallet what it is owed (`claim`). There is **no withdrawal instruction**: TTWO only
leaves the vault through `claim`, to the wallet of the leaf.

- Program id: `D1MRTECLfpTN6tNUTeAXwZ8t8FZ2WNzPSf9K5CDukweE`
- Initializer (admin): `HUv25kpB16CcBfWwx2BApSYqMpfGFWafLaB34ZzT1i8P`
- Merkle tree: leaf = `sha256(0x00 ‖ wallet ‖ cumulative u64 LE)`, node = `sha256(0x01 ‖ min ‖ max)`

## Instructions
| Instruction | Who | What |
|---|---|---|
| `initialize(operator, mint)` | initializer only, once | creates the config and the vault's TTWO account |
| `set_root(epoch, root, total_committed)` | operator | next epoch only, total never decreases, must be covered by the vault |
| `claim(cumulative, proof)` | anyone | pays the leaf's wallet `cumulative − already paid` |
| `set_operator`, `set_paused`, `propose_admin`, `accept_admin` | admin | pause stops `claim` only |

TTWO's issuer (Backpack Securities) keeps, as on every TTWO account, the power to pause transfers,
freeze accounts and move tokens as permanent delegate; this program cannot remove that.

## Build and test
```sh
anchor build --arch v2 -- --features test-initializer && cargo test   # LiteSVM tests
anchor build                                                          # deployable build
```

## Verify the deployed program
```sh
solana-verify verify-from-repo --program-id D1MRTECLfpTN6tNUTeAXwZ8t8FZ2WNzPSf9K5CDukweE \
  --library-name vicecards_vault https://github.com/Tezig13/contrat_vicecard
```
