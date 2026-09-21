# Writing an adapter

An adapter connects a platform (a CMS, a framework, a bot) to this engine so it can accept Monero.
Adapters are thin: the engine does the Monero work, the adapter just maps the platform's order flow
onto the engine. The adapter owns durable order state, concurrent settlement and
platform-specific fulfillment.

Reference adapters to copy from:

- [xmr-pay for WooCommerce](https://github.com/SlowBearDigger/xmr-pay-woocommerce): PHP inside WordPress.
- [xmr-pay for Laravel](https://github.com/SlowBearDigger/xmr-pay-laravel): a service + facade + config.

## The whole engine surface you need

You hold the merchant's primary **address** + private **view key** (config). Then:

```php
use XmrPay\Scanner;
use XmrPay\Util;

$s = new Scanner($nodes, $network);            // URLs or structured per-node authentication rows

$s->verify_keys($address, $viewKey);           // setup check: does the view key match the address?
$s->subaddress(0, $orderIndex, $viewKey, $address);  // a unique receiving address per order
$s->tip_height();                              // chain length; null unless every configured node answers
$s->verify_payment($txid, $address, $viewKey); // verify ONE tx paid an address ("I've paid" flow)
$s->scan_all($address, $viewKey, $from, $to);  // find every payment to an address in a height window
Util::summarize_payments($rows, $expPico, '0', $minConf);  // verdict over scanned rows (partials/top-ups)
Util::xmr_to_pico($xmr);  Util::pico_to_string($pico);     // exact money conversion
```

That is the entire contract. Everything else (RingCT commitment check, confirmations, time-locks,
burning-bug dedup, the state machine) happens inside those calls.

## The standard adapter flow

1. **Config**: collect the merchant's `address`, `view_key`, `nodes`, `network`, and a
   `min_confirmations`. Keep the view key and any node credentials out of version control.
2. **Per-order address**: when an order is created, assign it a unique integer index (your order
   id works) and call `subaddress(0, $index, $viewKey, $address)`. Require a non-null `tip_height()` and store it with the index as the order's birthday.
   Persist the mapping before presenting the payable order. Show the buyer the address as a QR / a
   `monero:` URI.
3. **Detect**: on a poll, a queued job, or a webhook, call `scan_all($subaddress, $viewKey,
   $birthday, $tip - 1, ['tip' => $tip])`. `tip_height()` is the chain length;
   the last existing block is `$tip - 1`. The returned `matches` are only for the
   scanned range. Persist them with `scanned_to`, retain earlier matches, revisit
   recent blocks for reorganisations and recompute confirmations before calling
   `Util::summarize_payments(...)`. Never skip an incomplete block. The shared
   adapter core's `Settler` implements this stateful loop.
4. **Settle**: when the verdict is paid, atomically claim its transaction and mark the order paid.
   Use database uniqueness and idempotent fulfillment, not only a prior-use query. The funds are
   already in the merchant's wallet; nothing routes through you.
5. **Refund (optional)**: Monero is irreversible and the sender is hidden, so refunds are manual:
   collect a return address from the buyer and have the merchant send it by hand.

Test storage, restart recovery, partial payments and concurrent settlement in the target platform.

## Hard rules

- **View key only.** Never ask for, accept, or store a spend key. The engine cannot move funds and
  neither should your adapter.
- **Never log or expose the view key.** Anyone with it can see every payment to that wallet.
- **Trust is the node.** A public node is fine for tips; for real revenue pass two or more nodes so
  every configured node must answer and agree. Agreement among dishonest or
  dependent nodes does not establish valid consensus. Document this for the
  merchant.
- **Test on stagenet first.** Use a stagenet address + node before mainnet.
- **The browser/client is never trusted.** Release goods only after the engine confirmed a real
  payment on-chain.

## Packaging

Require the engine and let Composer autoload it:

```
composer require slowbeardigger/xmr-pay
```

Requires PHP 7.4+ with the GMP and BCMath extensions. If your platform ships a zip without Composer
on the target (like a WordPress plugin), vendor the engine into your build and load it with a small
autoloader or `require`s; the WooCommerce plugin shows that pattern.
