# xmr-pay (PHP)

Non-custodial **Monero payment verification in pure PHP** — view-key only, **no
`monero-wallet-rpc`, no daemon on your box required, no server**. This is the PHP engine behind
[xmr-pay for WooCommerce](https://github.com/SlowBearDigger/xmr-pay-woocommerce), extracted as a
standalone Composer package so any PHP project can accept Monero: Laravel, Symfony, Joomla,
PrestaShop, Magento, OpenCart, or a plain checkout.

It is the exact mirror of the [xmr-pay JavaScript library](https://github.com/SlowBearDigger/xmr-pay)
— same money math, same invoice state machine — pinned by shared conformance vectors.

## How it differs from `monero-integrations/monerophp`

`monerophp` is a crypto toolbox + RPC clients (the building blocks). This package is the **layer
on top**: it answers *"is this order paid?"* — it derives a per-order subaddress, detects the
output against your view key, verifies the RingCT amount commitment, checks confirmations and
time-locks, dedupes the 2018 burning bug, and runs the invoice state machine. It builds on
monerophp's primitives (see `third-party/monero/ATTRIBUTION.md`); it does not reimplement them.

## Requirements

- PHP 7.4+
- ext-gmp (the money math) and ext-bcmath (base58)
- a Monero node to read the chain (a public one is fine; for serious money run your own or require
  two to agree). No wallet-rpc.

## Install

```
composer require slowbeardigger/xmr-pay
```

## What's here

- `XmrPay\Util` — money math, the invoice state machine (`to_invoice_state`), claim-link expiry,
  multi-transaction payment aggregation (`summarize_payments`), CSV safety. Pure, no network.
- `XmrPay\Scanner` — the verification engine: fetch a tx from a node, detect a payment to your
  address/subaddress, decode + verify the amount, report confirmations / lock / double-spend.
  HTTP works out of the box via PHP streams (no WordPress); inside WordPress it transparently uses
  `wp_safe_remote_*`.

## Adapters

Connecting a platform is thin: the engine does the Monero work, an adapter just maps the platform's
order flow onto a handful of calls. See [docs/WRITING-AN-ADAPTER.md](docs/WRITING-AN-ADAPTER.md) for
the full contract and a minimal skeleton. Reference adapters:

- [xmr-pay for WooCommerce](https://github.com/SlowBearDigger/xmr-pay-woocommerce) — PHP inside WordPress.
- [xmr-pay for Laravel](https://github.com/SlowBearDigger/xmr-pay-laravel) — a service + facade + config.

WHMCS, Joomla, PrestaShop, OpenCart, and others are good next adapters and welcome contributions.

## Security model

- **View key only.** The package never asks for or holds a spend key. It can read incoming
  payments; it can never move funds.
- **The amount is proven, not claimed** (RingCT commitment check). It fails closed: commitment,
  confirmations, no time-lock, and no double-count must all pass, or the payment is not credited.
- **You trust the node you point it at.** Use your own, or require agreement across nodes.

## Status

Extracted from the WooCommerce plugin (the proven engine). Pure-logic tests (`tests/`: state,
util, aggregation, refund, crypto) run under plain `php` with no Composer:

```
composer test          # or: php tests/aggregation.test.php
```

The WooCommerce plugin will be refactored to consume this package (dogfood), so there is one
engine, not two copies.
