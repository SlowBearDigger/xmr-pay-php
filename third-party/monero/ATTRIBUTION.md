# Vendored crypto — attribution

These files are the Monero cryptography primitives this package builds on. They are NOT ours:

- `Cryptonote.php`, `base58.php`, `Varint.php`, `ed25519.php` — from
  [monero-integrations/monerophp](https://github.com/monero-integrations/monerophp) (MIT),
  namespace `MoneroIntegrations\MoneroPhp`.
- `Keccak.php` — from [kornrunner/php-keccak](https://github.com/kornrunner/php-keccak) (MIT),
  namespace `kornrunner`.

xmr-pay is the **verification engine on top of** these primitives (subaddress derivation,
output detection, RingCT commitment check, confirmation/lock logic, aggregation, state machine) —
the classic primitive files are vendored.

The recovered snapshot removed WordPress direct-access guards and contains local attribution
headers. Its original vendoring commits were not recorded, so a claim that guard removal was
the only upstream modification is not established. This review changes no vendored crypto
operations. The source files retain their existing notices; complete MIT license copies are
distributed in `licenses/MIT-MONEROPHP.txt` and `licenses/MIT-KECCAK.txt` at the package root.

The monerophp license copy was retrieved at commit
`1ced7fb4b785a0d7d50ebb1bdbd6682f803c73bb`; the Keccak license copy at
`a166c2eb859a21089a6e004949d35b5f9dd0687b`. These pins identify the license documents,
not the unrecorded versions from which the recovered PHP files were originally copied.

## Source comparison on 2026-10-10

Fresh checkouts of those exact commits provide a concrete comparison baseline:

- `Cryptonote.php`, `Varint.php`, and `ed25519.php` differ only by added blank lines.
- `base58.php` additionally rejects a failed alphabet lookup explicitly and excludes
  the extra iteration beyond the full-block count.
- `Keccak.php` adds local provenance comments and uses `ord()` instead of an integer
  cast for the final-byte padding operation in its 32-bit implementation path.

These observations replace the unsupported claim that only a WordPress guard changed.
They establish source correspondence against the pinned baseline, not historical
proof of which commit the original vendoring process used. Diff evidence and hashes
are under `runtime/primitives-review-20261010` in the parent laboratory workspace.

A future version may replace this vendored copy with a Composer dependency on
`monero-integrations/monerophp` directly.
