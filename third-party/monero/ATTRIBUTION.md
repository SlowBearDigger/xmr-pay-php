# Vendored crypto — attribution

These files are the Monero cryptography primitives this package builds on. They are NOT ours:

- `Cryptonote.php`, `base58.php`, `Varint.php`, `ed25519.php` — from
  [monero-integrations/monerophp](https://github.com/monero-integrations/monerophp) (MIT),
  namespace `MoneroIntegrations\MoneroPhp`.
- `Keccak.php` — from [kornrunner/php-keccak](https://github.com/kornrunner/php-keccak) (MIT),
  namespace `kornrunner`.

xmr-pay is the **verification engine on top of** these primitives (subaddress derivation,
output detection, RingCT commitment check, confirmation/lock logic, aggregation, state machine) —
it does not reimplement the crypto.

**Only modification from upstream:** the WordPress `if ( ! defined( 'ABSPATH' ) ) { exit; }`
direct-access guard was removed (it is meaningless outside WordPress and would halt the library on
load). The cryptographic code is otherwise unchanged.

A future version may replace this vendored copy with a Composer dependency on
`monero-integrations/monerophp` directly.
