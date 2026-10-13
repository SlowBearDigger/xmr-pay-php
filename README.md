# xmr-pay (PHP)

Non-custodial **Monero payment verification in pure PHP**: view-key only, **no
`monero-wallet-rpc` or separate payment daemon required**. It runs in your PHP server. This is the PHP engine behind
[xmr-pay for WooCommerce](https://github.com/SlowBearDigger/xmr-pay-woocommerce), extracted as a
standalone Composer package so any PHP project can accept Monero: Laravel, Symfony, Joomla,
PrestaShop, Magento, OpenCart, or a plain checkout.

It shares money and invoice-state contracts with the
[xmr-pay JavaScript library](https://github.com/SlowBearDigger/xmr-pay), checked by
conformance vectors. Transports, scanning and node-agreement policies differ.

## How it differs from `monero-integrations/monerophp`

`monerophp` is a crypto toolbox + RPC clients (the building blocks). This package is the **layer
on top**: it answers *"is this order paid?"*: it derives a per-order subaddress, detects the
output against your view key, verifies the RingCT amount commitment, checks confirmations and
time-locks, dedupes the 2018 burning bug, and runs the invoice state machine. It builds on
monerophp's vendored legacy primitives (see `third-party/monero/ATTRIBUTION.md`).

This checkout contains the classic RingCT payment engine for Monero mainnet.
It retains exact amounts, output identities, node agreement and resumable block
scanning. Unknown output formats prevent a scan from being marked complete.
Experimental CARROT/FCMP development is preserved on `integration/carrot-fcmp`.

The root MIT license covers original project code. The vendored primitives retain
their copyright notices and complete MIT license texts under `licenses/`.
See [the package notice](NOTICE) and [primitive attribution](third-party/monero/ATTRIBUTION.md).

## Requirements

- PHP 7.4+
- ext-gmp (money math), ext-bcmath (base58) and ext-mbstring (Keccak)
- a Monero node to read the chain (a public one is fine; for serious money run your own or require
  two to agree). No wallet-rpc.

## Install this checkout

Unpack the local archive and `require '/path/to/xmr-pay-php/autoload.php';`.
For Composer, use a local path repository pointing to this checkout.
`composer require slowbeardigger/xmr-pay` installs the published release instead.

## What's here

- `XmrPay\Util`: money math, the invoice state machine (`to_invoice_state`), claim-link expiry,
  multi-transaction payment aggregation (`summarize_payments`), CSV safety. Pure, no network.
- `XmrPay\Scanner`: the verification engine: fetch a tx from a node, detect a payment to your
  address/subaddress, decode + verify the amount, report confirmations / lock / double-spend.
  HTTP uses cURL when available, or PHP streams for supported requests. Inside
  WordPress, unauthenticated requests use `wp_safe_remote_*`. Digest requires cURL.

## Adapters

Connecting a platform is thin: the engine does the Monero work, an adapter just maps the platform's
order flow onto a handful of calls. See [docs/WRITING-AN-ADAPTER.md](docs/WRITING-AN-ADAPTER.md) for
the full contract and a minimal skeleton. Reference adapters:

- [xmr-pay for WooCommerce](https://github.com/SlowBearDigger/xmr-pay-woocommerce): PHP inside WordPress.
- [xmr-pay for Laravel](https://github.com/SlowBearDigger/xmr-pay-laravel): a service + facade + config.

HikaShop and VirtueMart adapters also exist and share `xmr-pay-adapter-core`.
Blesta also integrates this scanner through its native view-key gateway.

## Security model

- **View key only.** The package never asks for or holds a spend key. It can read incoming
  payments; it can never move funds.
- **The amount is proven, not claimed** (RingCT commitment check). It fails closed: commitment,
  confirmations, no time-lock, and no double-count must all pass, or the payment is not credited.
- **You trust the node you point it at.** The scanner requires all configured nodes to respond and agree. Use independent,
  trusted nodes; agreement does not validate consensus independently.

## Status

This release branch contains the runtime and its required license notices.
Validation suites and integration laboratories are maintained separately.

Joomla packages vendor this engine at build time. WooCommerce currently maintains
a WordPress-specific scanner; changes to shared behavior need checks in both.
