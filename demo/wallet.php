<?php
// xmr-pay-php demo — stagenet wallet generator.
// generates a fresh stagenet address + keys in pure PHP, saves to demo/wallet.json.
// no monero-wallet-cli, no daemon, no Composer.
//
// usage:
//   php demo/wallet.php

$root = dirname(__DIR__);
require_once $root . '/third-party/monero/base58.php';
require_once $root . '/third-party/monero/Varint.php';
require_once $root . '/third-party/monero/Keccak.php';
require_once $root . '/third-party/monero/ed25519.php';
require_once $root . '/third-party/monero/Cryptonote.php';
require_once $root . '/src/Util.php';
require_once $root . '/src/Scanner.php';

use XmrPay\Util;
use XmrPay\Scanner;

if (!Util::crypto_ready()) {
    fwrite(STDERR, "need ext-gmp + ext-bcmath\n");
    exit(1);
}

$out = __DIR__ . '/wallet.json';

if (file_exists($out)) {
    $w = json_decode(file_get_contents($out), true);
    echo "wallet already exists — delete demo/wallet.json to regenerate.\n\n";
    echo "  address  : " . $w['address'] . "\n";
    echo "  view key : " . $w['view_key'] . "\n";
    echo "\n";
    exit(0);
}

$cn   = new MoneroIntegrations\MoneroPhp\Cryptonote('stagenet');
$seed = $cn->gen_new_hex_seed();
$keys = $cn->gen_private_keys($seed);

$spend_priv = $keys['spendKey'];
$view_priv  = $keys['viewKey'];
$spend_pub  = $cn->pk_from_sk($spend_priv);
$view_pub   = $cn->pk_from_sk($view_priv);
$address    = $cn->encode_address($spend_pub, $view_pub);

// quick sanity: view key should round-trip via Scanner::verify_keys
$s  = new Scanner('http://node2.monerodevs.org:38089', 'stagenet', 5);
$vk = $s->verify_keys($address, $view_priv);
if (!$vk['address_valid'] || !$vk['key_match']) {
    fwrite(STDERR, "generated keys failed self-check — should not happen\n");
    exit(1);
}

$wallet = [
    'network'   => 'stagenet',
    'address'   => $address,
    'spend_key' => $spend_priv,   // keep safe — can spend funds
    'view_key'  => $view_priv,    // used by scanner — view only
    'seed'      => $seed,         // backup: gen_private_keys(seed) reproduces the keys
];

file_put_contents($out, json_encode($wallet, JSON_PRETTY_PRINT) . "\n");
chmod($out, 0600);

echo "\n";
echo "  stagenet wallet generated\n";
echo "  " . str_repeat('-', 66) . "\n";
echo "  address  : $address\n";
echo "  view key : $view_priv  (view-only, used by scanner)\n";
echo "  spend key: $spend_priv  (keep secret)\n";
echo "  seed     : $seed\n";
echo "  saved to : demo/wallet.json  (chmod 600)\n";
echo "  " . str_repeat('-', 66) . "\n\n";
echo "  fund it with stagenet XMR from a faucet:\n";
echo "    https://stagenet.xmr.ditatompel.com\n";
echo "    https://stagenet-faucet.xmr-tw.org\n\n";
echo "  then run:  php demo/scan.php\n\n";
