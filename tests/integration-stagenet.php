<?php
// LIVE integration test — verifies REAL stagenet payments against a live Monero node, end to end,
// through the extracted engine (no WordPress). Cross-checks parity with the JavaScript library:
// the same on-chain payments the JS scanner sees must verify here with the same total.
//
// Needs tests/stagenet.config.php (gitignored — copy stagenet.config.example.php and fill it from
// your stagenet wallet's address + PRIVATE VIEW KEY). With no config it SKIPS, so the suite stays
// green offline / in CI without secrets.
//
//   php tests/integration-stagenet.php

require_once __DIR__ . '/bootstrap.php';

$cfgPath = __DIR__ . '/stagenet.config.php';
if (!file_exists($cfgPath)) {
    echo "SKIP  integration-stagenet — no tests/stagenet.config.php (copy stagenet.config.example.php)\n";
    exit(0);
}
$cfg = require $cfgPath;

$pass = 0; $fail = 0;
function ok($name, $cond, $extra = '') {
    global $pass, $fail;
    if ($cond) { $pass++; echo "PASS  $name\n"; }
    else { $fail++; echo "FAIL  $name" . ($extra !== '' ? "  — $extra" : '') . "\n"; }
}

$s = new XmrPay\Scanner($cfg['node'], 'stagenet', 25);

// 1. the live node answers (tip_height fails over across all configured nodes), and the view key
//    really belongs to the primary address (offline crypto).
$tip = $s->tip_height();
ok('live stagenet node reachable (failover)', is_int($tip) && $tip > 0, 'tip=' . var_export($tip, true));
$vk = $s->verify_keys($cfg['primaryAddress'], $cfg['viewKey']);
ok('view key matches the primary address', !empty($vk['address_valid']) && !empty($vk['key_match']), json_encode($vk));

// 2. the order subaddress derives from (primary address + view key) ALONE — non-custodial.
$derived = $s->subaddress(0, (int) $cfg['orderSubaddressIndex'], $cfg['viewKey'], $cfg['primaryAddress']);
$derivedAddr = is_array($derived) ? ($derived['address'] ?? '') : (string) $derived;
ok('derived order subaddress matches the funded one', $derivedAddr === $cfg['orderSubaddress'], $derivedAddr);

// 3. each REAL faucet payment verifies on-chain: detected, amount committed, deeply confirmed.
$total = gmp_init(0);
foreach ($cfg['txids'] as $txid) {
    $r = $s->verify_payment($txid, $cfg['orderSubaddress'], $cfg['viewKey'], ['tip' => $tip, 'require_commitment' => true]);
    $good = !empty($r['found']) && !empty($r['commitment_ok']) && empty($r['locked']);
    ok("verify_payment $txid — found, committed, unlocked", $good, json_encode($r));
    if (!empty($r['found'])) {
        $total = gmp_add($total, gmp_init((string) $r['amount_atomic']));
        ok("  $txid confirmations > 1 (settled)", isset($r['confirmations']) && (int) $r['confirmations'] > 1, (string) ($r['confirmations'] ?? 'null'));
    }
}

// 4. PARITY: the summed amount equals what the JS engine reported for the same subaddress.
$totalXmr = XmrPay\Util::pico_to_string(gmp_strval($total));
ok('summed amount matches expected total (JS<->PHP parity)', $totalXmr === $cfg['expectedTotalXmr'], "$totalXmr vs {$cfg['expectedTotalXmr']}");

echo "\n" . ($fail ? "FAILED ($fail)" : 'ALL GREEN') . "  $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
