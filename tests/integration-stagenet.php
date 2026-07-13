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

$runs = isset($cfg['runs']) && is_array($cfg['runs']) ? $cfg['runs'] : [
    'legacy' => [
        'node'                 => $cfg['node'],
        'auth'                 => 'none',
        'orderSubaddress'      => $cfg['orderSubaddress'],
        'orderSubaddressIndex' => $cfg['orderSubaddressIndex'],
        'txids'                => $cfg['txids'],
        'expectedTotalXmr'     => $cfg['expectedTotalXmr'],
    ],
];

foreach ($runs as $name => $run) {
    $failBeforeRun = $fail;
    if (!empty($run['artifact']) && is_file($run['artifact'])) {
        unlink($run['artifact']);
    }

    $expectedAuth = isset($run['auth']) ? (string) $run['auth'] : 'none';
    $normalizedNodes = XmrPay\NodeConfig::normalizeList($run['node']);
    $authMatches = true;
    foreach ($normalizedNodes as $normalizedNode) {
        if ($normalizedNode['auth'] !== $expectedAuth) { $authMatches = false; break; }
    }
    ok("$name: every configured node uses $expectedAuth auth", $authMatches);

    $s = new XmrPay\Scanner($run['node'], 'stagenet', 25);

    // 1. every run reaches stagenet using only its configured node records.
    $tip = $s->tip_height();
    ok("$name: live stagenet node reachable", is_int($tip) && $tip > 0, 'tip=' . var_export($tip, true));

    // 2. the common private view key belongs to the primary address and derives this run's order.
    $vk = $s->verify_keys($cfg['primaryAddress'], $cfg['viewKey']);
    ok("$name: view key matches the primary address", !empty($vk['address_valid']) && !empty($vk['key_match']), json_encode($vk));
    $derived = $s->subaddress(0, (int) $run['orderSubaddressIndex'], $cfg['viewKey'], $cfg['primaryAddress']);
    $derivedAddr = is_array($derived) ? ($derived['address'] ?? '') : (string) $derived;
    ok("$name: derived order subaddress matches", $derivedAddr === $run['orderSubaddress'], $derivedAddr);

    // 3. each real payment is committed, unlocked, settled, and repeatable without changing result.
    $total = gmp_init(0);
    $minConfirmations = null;
    $idempotent = true;
    foreach ($run['txids'] as $txid) {
        $r = $s->verify_payment($txid, $run['orderSubaddress'], $cfg['viewKey'], ['tip' => $tip, 'require_commitment' => true]);
        $again = $s->verify_payment($txid, $run['orderSubaddress'], $cfg['viewKey'], ['tip' => $tip, 'require_commitment' => true]);
        $good = !empty($r['found']) && !empty($r['commitment_ok']) && empty($r['locked']);
        $same = $good && $r['amount_atomic'] === ($again['amount_atomic'] ?? null) && $r['out_key'] === ($again['out_key'] ?? null);
        ok("$name: verify_payment $txid found, committed, unlocked", $good, json_encode($r));
        ok("$name: verify_payment $txid is idempotent", $same, json_encode($again));
        $idempotent = $idempotent && $same;
        if (!empty($r['found'])) {
            $total = gmp_add($total, gmp_init((string) $r['amount_atomic']));
            $confirmations = isset($r['confirmations']) ? (int) $r['confirmations'] : 0;
            $minConfirmations = null === $minConfirmations ? $confirmations : min($minConfirmations, $confirmations);
            ok("$name: $txid confirmations > 1 (settled)", $confirmations > 1, (string) $confirmations);
        }
    }

    // 4. the exact atomic total matches the expected amount.
    $totalAtomic = gmp_strval($total);
    $totalXmr = XmrPay\Util::pico_to_string($totalAtomic);
    ok("$name: summed amount matches expected total", $totalXmr === $run['expectedTotalXmr'], "$totalXmr vs {$run['expectedTotalXmr']}");

    if (!empty($run['artifact']) && $fail === $failBeforeRun) {
        $artifact = [
            'platform'           => 'xmr-pay-php',
            'auth_scheme'        => $expectedAuth,
            'txids'              => array_values($run['txids']),
            'address'            => $run['orderSubaddress'],
            'amount_atomic'      => $totalAtomic,
            'confirmations'      => (int) $minConfirmations,
            'settlement_state'   => $minConfirmations > 1 ? 'settled' : 'pending',
            'idempotent_recheck' => $idempotent,
        ];
        file_put_contents($run['artifact'], json_encode($artifact, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    }
}

echo "\n" . ($fail ? "FAILED ($fail)" : 'ALL GREEN') . "  $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
