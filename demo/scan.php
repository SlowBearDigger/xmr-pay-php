<?php
// xmr-pay-php demo — standalone stagenet scanner.
// no Composer, no backend, no wallet-rpc. only PHP + GMP + BCMath.
//
// usage:
//   php demo/scan.php
//
// or set env vars (recommended — keeps secrets out of the file):
//   XMR_ADDRESS=5...  XMR_VIEWKEY=abc...  php demo/scan.php
//
// copies to any machine (or PS4) that has a php binary compiled with --enable-gmp --enable-bcmath.

$root = dirname(__DIR__);
require_once $root . '/third-party/monero/base58.php';
require_once $root . '/third-party/monero/Varint.php';
require_once $root . '/third-party/monero/Keccak.php';
require_once $root . '/third-party/monero/ed25519.php';
require_once $root . '/third-party/monero/Cryptonote.php';
require_once $root . '/src/Util.php';
require_once $root . '/src/Scanner.php';

use XmrPay\Scanner;
use XmrPay\Util;

// ---------- config ----------
// stagenet public nodes (comma-separated for failover + tip cross-check)
$NODES = getenv('XMR_NODES') ?: 'http://node2.monerodevs.org:38089,http://node.monerodevs.org:38089';

// wallet credentials — loaded from env, demo/wallet.json (auto-generated), or set manually.
// run `php demo/wallet.php` first to generate a stagenet wallet.
$ADDRESS  = getenv('XMR_ADDRESS')  ?: '';
$VIEW_KEY = getenv('XMR_VIEWKEY') ?: '';

if ($ADDRESS === '' || $VIEW_KEY === '') {
    $wf = __DIR__ . '/wallet.json';
    if (file_exists($wf)) {
        $w        = json_decode(file_get_contents($wf), true);
        $ADDRESS  = $w['address']  ?? '';
        $VIEW_KEY = $w['view_key'] ?? '';
    }
}

// subaddress index to watch (0 = the primary address itself)
$SUBADDR_INDEX = (int)(getenv('XMR_INDEX') ?: 0);

// how many blocks to scan per tick (stagenet ~2 min / block)
$BLOCKS_PER_TICK = (int)(getenv('XMR_BLOCKS') ?: 20);

// pause between ticks when caught up to chain tip (seconds)
$SLEEP = (int)(getenv('XMR_SLEEP') ?: 30);

// minimum confirmations to consider a payment settled
$MIN_CONF = (int)(getenv('XMR_MIN_CONF') ?: 10);
// ---------- end config ----------

if ($ADDRESS === '' || $VIEW_KEY === '') {
    fwrite(STDERR, "set XMR_ADDRESS and XMR_VIEWKEY (env) or edit the config block at the top.\n");
    exit(1);
}

if (!Util::crypto_ready()) {
    fwrite(STDERR, "PHP extensions missing — need both ext-gmp and ext-bcmath.\n");
    fwrite(STDERR, "compile php with: --with-gmp --enable-bcmath\n");
    exit(1);
}

$scanner = new Scanner($NODES, 'stagenet', 20);

$vk = $scanner->verify_keys($ADDRESS, $VIEW_KEY);
if (!$vk['address_valid'] || !$vk['key_match']) {
    fwrite(STDERR, "view key does not match the address — check XMR_ADDRESS / XMR_VIEWKEY.\n");
    fwrite(STDERR, json_encode($vk) . "\n");
    exit(1);
}

$watch_address = $ADDRESS;
if ($SUBADDR_INDEX > 0) {
    $sub = $scanner->subaddress(0, $SUBADDR_INDEX, $VIEW_KEY, $ADDRESS);
    if (!$sub) {
        fwrite(STDERR, "could not derive subaddress #$SUBADDR_INDEX\n");
        exit(1);
    }
    $watch_address = $sub['address'];
}

$tip = $scanner->tip_height();
if (!$tip) {
    fwrite(STDERR, "could not reach any stagenet node — check network / nodes.\n");
    exit(1);
}

// start 100 blocks back so any recent payment is caught on first scan
$from = max(1, $tip - 100);

$label = $SUBADDR_INDEX > 0 ? "subaddress #$SUBADDR_INDEX" : 'primary address';

echo "\n";
echo "  xmr-pay-php  --  stagenet scanner\n";
echo "  " . str_repeat('-', 52) . "\n";
echo "  address : $watch_address\n";
echo "          ($label)\n";
echo "  nodes   : $NODES\n";
echo "  tip     : $tip\n";
echo "  from    : block $from\n";
echo "  " . str_repeat('-', 52) . "\n\n";

$total_pico    = gmp_init(0);
$seen_out_keys = [];   // dedup by one-time output key (burning-bug guard)

while (true) {
    $new_tip = $scanner->tip_height();
    if ($new_tip) { $tip = $new_tip; }

    $to = min($tip - 1, $from + $BLOCKS_PER_TICK - 1);

    if ($from > $to) {
        echo "[" . date('H:i:s') . "] at tip ($tip) -- sleeping {$SLEEP}s\n";
        sleep($SLEEP);
        continue;
    }

    echo "[" . date('H:i:s') . "] blocks $from-$to (tip $tip)... ";
    flush();

    $result = $scanner->scan_all($watch_address, $VIEW_KEY, $from, $to, [
        'max_blocks'         => $BLOCKS_PER_TICK,
        'time_budget'        => 25.0,
        'require_commitment' => true,
        'tip'                => $tip,
    ]);

    $n = count($result['matches']);
    echo ($n > 0 ? "$n payment(s) found" : 'nothing') . "\n";

    foreach ($result['matches'] as $m) {
        $dedup_key = isset($m['out_key']) && $m['out_key'] !== '' ? $m['out_key'] : $m['txid'];
        if (isset($seen_out_keys[$dedup_key])) { continue; }
        $seen_out_keys[$dedup_key] = true;

        $conf   = isset($m['confirmations']) ? (int)$m['confirmations'] : 0;
        $amount = Util::pico_to_string($m['amount_atomic']);
        $settled = !$m['locked'] && $conf >= $MIN_CONF;

        $total_pico = gmp_add($total_pico, gmp_init((string)$m['amount_atomic']));

        echo "\n";
        echo "  +++ PAYMENT +++\n";
        echo "  txid   : " . ($m['txid'] ?? '?') . "\n";
        echo "  amount : $amount XMR\n";
        echo "  confs  : $conf / $MIN_CONF  " . ($settled ? '[SETTLED]' : '[pending]') . "\n";
        echo "  block  : " . ($m['block_height'] ?? '?') . "\n";
        echo "  commit : " . ($m['commitment_ok'] ? 'ok' : 'FAIL') . "\n";
        echo "  locked : " . ($m['locked'] ? 'yes' : 'no') . "\n";
        echo "  TOTAL  : " . Util::pico_to_string(gmp_strval($total_pico)) . " XMR\n";
        echo "\n";
    }

    $from = (isset($result['scanned_to']) ? (int)$result['scanned_to'] : $to) + 1;

    if ($from > $tip) {
        echo "[" . date('H:i:s') . "] caught up -- sleeping {$SLEEP}s\n";
        sleep($SLEEP);
    }
}
