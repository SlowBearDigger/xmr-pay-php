<?php
/**
 * Adversarial tests for XmrPay_Util::summarize_payments — the WP-native multi-tx
 * settlement verdict (installments / top-ups). Mirrors the lib's adversarial-stress
 * suite: these try to BREAK the money path, not confirm the happy path.
 *   php tests/aggregation.test.php
 */

define( 'ABSPATH', __DIR__ . '/' );   // satisfy the includes' direct-access guard
if ( ! function_exists( 'wp_parse_url' ) ) { function wp_parse_url( $url, $component = -1 ) { return parse_url( (string) $url, $component ); } }
require_once __DIR__ . '/bootstrap.php';

$pass = 0; $fail = 0;
function ok( $name, $cond, $extra = '' ) {
	global $pass, $fail;
	if ( $cond ) { $pass++; echo "PASS  $name\n"; }
	else { $fail++; echo "FAIL  $name" . ( $extra !== '' ? "  — $extra" : '' ) . "\n"; }
}
// a committed, confirmed, unlocked row by default; override any field.
function row( $txid, $amt, $over = array() ) {
	return array_merge( array(
		'txid'          => $txid,
		'amount_atomic' => (string) $amt,
		'confirmations' => 10,
		'in_pool'       => false,
		'locked'        => false,
		'commitment_ok' => true,
	), $over );
}
// project the verdict onto the fields a store settles on (for order-independence).
function verdict_str( $r ) { return $r['paid'] . '|' . $r['status'] . '|' . $r['received_pico'] . '|' . $r['shortfall_pico']; }

// ── 1. INSTALLMENTS: two confirmed txs that SUM to the price → paid ──
$r = XmrPay_Util::summarize_payments( array( row( 'a', 60 ), row( 'b', 40 ) ), '100', '0', 1 );
ok( 'installments: 60 + 40 = 100 → paid', $r['paid'] === true && $r['received_pico'] === '100', verdict_str( $r ) );

// ── 2. DUST-THEN-FULL: the exact bug the single-tx scanner had ──
// a tiny "test" payment first, then the rest in another tx. the SUM must complete it,
// not latch onto the dust forever.
$r = XmrPay_Util::summarize_payments( array( row( 'dust', 1 ), row( 'rest', 100 ) ), '101', '0', 1 );
ok( 'dust test tx then full payment → paid (no latch to the dust)', $r['paid'] === true && $r['received_pico'] === '101', verdict_str( $r ) );

// ── 3. ORDER-INDEPENDENCE: shuffling rows never changes the verdict ──
$rows = array(
	row( 'a', 30, array( 'confirmations' => 2 ) ),
	row( 'a', 30, array( 'in_pool' => true, 'confirmations' => null ) ), // same tx, pool copy
	row( 'b', 70 ),
	row( '', 5 ), // empty txid, never deduped
);
$a = verdict_str( XmrPay_Util::summarize_payments( $rows, '100', '0', 1 ) );
$b = verdict_str( XmrPay_Util::summarize_payments( array_reverse( $rows ), '100', '0', 1 ) );
ok( 'order-independence: reversing the rows is the same verdict', $a === $b, "$a  vs  $b" );

// ── 3b. ORDER-INDEPENDENCE on LOCK STATUS (the regression fast-check caught in the lib) ──
// two copies of one txid that differ ONLY in lock status must dedup deterministically:
// the conservative (locked) reading wins regardless of order, so neither order pays.
$la = row( 'L', 100, array( 'locked' => true ) );
$lb = row( 'L', 100, array( 'locked' => false ) );
$x  = verdict_str( XmrPay_Util::summarize_payments( array( $la, $lb ), '100', '0', 1 ) );
$y  = verdict_str( XmrPay_Util::summarize_payments( array( $lb, $la ), '100', '0', 1 ) );
ok( 'order-independence: same txid differing only in lock → same verdict (held locked)', $x === $y && strpos( $x, 'locked' ) !== false, "$x  vs  $y" );

// ── 3c. BURNING BUG: two outputs sharing a one-time key (P), in DIFFERENT txids ──
// the 2018 Monero attack: an attacker crafts two outputs to the subaddress with the same
// output key P across two txs; each has a valid commitment but on-chain only ONE is
// spendable (shared key image). Deduping by txid alone credits both = direct loss. We
// dedup by P, so it counts once.
$b1 = XmrPay_Util::summarize_payments( array(
	row( 'txA', 100, array( 'out_key' => 'P_same' ) ),
	row( 'txB', 100, array( 'out_key' => 'P_same' ) ),
), '100', '0', 1 );
ok( 'burning bug: same output key across two txids is credited ONCE', $b1['received_pico'] === '100' && $b1['paid'] === true, verdict_str( $b1 ) );

// the actual exploit: a 200 order must NOT settle on two same-key 100 outputs (100 real).
$b2 = XmrPay_Util::summarize_payments( array(
	row( 'txA', 100, array( 'out_key' => 'P_same' ) ),
	row( 'txB', 100, array( 'out_key' => 'P_same' ) ),
), '200', '0', 1 );
ok( 'burning bug: a 200 order is NOT settled by two same-key 100 outputs', $b2['paid'] === false && $b2['received_pico'] === '100', verdict_str( $b2 ) );

// distinct output keys are two real payments and still sum.
$b3 = XmrPay_Util::summarize_payments( array(
	row( 'txA', 100, array( 'out_key' => 'P1' ) ),
	row( 'txB', 100, array( 'out_key' => 'P2' ) ),
), '200', '0', 1 );
ok( 'distinct output keys (two real payments) still sum to paid', $b3['paid'] === true && $b3['received_pico'] === '200', verdict_str( $b3 ) );

// ── 4. IN/POOL DEDUP: same txid as confirmed AND pool → counted once, confirmed wins ──
$conf = row( 't', 50 );
$pool = row( 't', 50, array( 'in_pool' => true, 'confirmations' => null ) );
$x = XmrPay_Util::summarize_payments( array( $conf, $pool ), '50', '0', 1 );
$y = XmrPay_Util::summarize_payments( array( $pool, $conf ), '50', '0', 1 );
ok( 'in/pool duplicate counted once, confirmed wins regardless of order',
	$x['paid'] === true && $y['paid'] === true && $x['received_pico'] === '50' && $y['received_pico'] === '50',
	verdict_str( $x ) . '  |  ' . verdict_str( $y ) );

// ── 5. BYZANTINE same-txid DIFFERENT amounts → smaller wins, order-independent ──
$small = row( 'z', 1 );
$big   = row( 'z', 999999 );
$a = verdict_str( XmrPay_Util::summarize_payments( array( $small, $big ), '1000', '0', 1 ) );
$b = verdict_str( XmrPay_Util::summarize_payments( array( $big, $small ), '1000', '0', 1 ) );
ok( 'byzantine same-txid different-amount: order-independent verdict', $a === $b, "$a  vs  $b" );
$z = XmrPay_Util::summarize_payments( array( $big, $small ), '1000', '0', 1 );
ok( 'byzantine: the bogus 999999 never settles a 1000 order', $z['paid'] === false && $z['received_pico'] === '1', verdict_str( $z ) );

// ── 6. UNCOMMITTED output is NEVER credited (forged-amount guard) ──
$r = XmrPay_Util::summarize_payments( array( row( 'forged', 1000, array( 'commitment_ok' => false ) ) ), '1000', '0', 1 );
ok( 'uncommitted (commitment_ok=false) amount is never credited', $r['paid'] === false && $r['received_pico'] === '0', verdict_str( $r ) );

// ── 7. LOCKED funds are seen but never paid ──
$r = XmrPay_Util::summarize_payments( array( row( 'L', 100, array( 'locked' => true ) ) ), '100', '0', 1 );
ok( 'time-locked output → not paid, status locked', $r['paid'] === false && $r['status'] === 'locked', verdict_str( $r ) );

// ── 8. PARTIAL: under the price → not paid, but seen > 0 (so expiry won't cancel) ──
$r = XmrPay_Util::summarize_payments( array( row( 'p', 40 ) ), '100', '0', 1 );
ok( 'partial payment → not paid, status partial, seen > 0', $r['paid'] === false && $r['status'] === 'partial' && $r['seen_pico'] === '40', verdict_str( $r ) );

// ── 9. CONFIRMATIONS gate: enough money but below min_conf → mempool/unconfirmed ──
$r = XmrPay_Util::summarize_payments( array( row( 'c', 100, array( 'confirmations' => 0, 'in_pool' => true ) ) ), '100', '0', 2 );
ok( 'full amount in mempool, below min_conf → not paid (mempool)', $r['paid'] === false && $r['status'] === 'mempool', verdict_str( $r ) );

// ── 10. TOLERANCE: within tolerance settles; tolerance can never reach the price ──
$r = XmrPay_Util::summarize_payments( array( row( 't', 99 ) ), '100', '1', 1 );
ok( 'within tolerance (99 of 100, tol 1) → paid', $r['paid'] === true, verdict_str( $r ) );
// the clamp's job is to keep the threshold >= 1 pico so an absurd tolerance can never
// settle an order on NOTHING — zero received must still never read as paid.
$r = XmrPay_Util::summarize_payments( array(), '100', '100', 1 );
ok( 'absurd tolerance + zero received → NOT paid (threshold never reaches 0)', $r['paid'] === false && $r['received_pico'] === '0', verdict_str( $r ) );

// ── 11. FUZZ: credited never exceeds the per-txid max committed-confirmed total ──
mt_srand( 20260620 );
$fuzz_ok = true; $counter = 0;
for ( $iter = 0; $iter < 4000; $iter++ ) {
	$rows = array();
	$n = mt_rand( 0, 8 );
	for ( $i = 0; $i < $n; $i++ ) {
		$rows[] = array(
			'txid'          => array( 'a', 'b', 'c', '' )[ mt_rand( 0, 3 ) ],
			'amount_atomic' => (string) mt_rand( 0, 1000 ),
			'confirmations' => mt_rand( 0, 1 ) ? mt_rand( 0, 20 ) : null,
			'in_pool'       => (bool) mt_rand( 0, 1 ),
			'locked'        => (bool) mt_rand( 0, 1 ),
			'commitment_ok' => (bool) mt_rand( 0, 1 ),
		);
	}
	$mc  = mt_rand( 1, 5 );
	$sum = XmrPay_Util::summarize_payments( $rows, '1', '0', $mc );

	// independent bound: per distinct REAL txid, the largest committed+confirmed+unlocked
	// amount among its copies; empty-txid rows each count on their own.
	$bound = gmp_init( 0 );
	$max_by = array();
	foreach ( $rows as $t ) {
		$amt = preg_match( '/^\d+$/', (string) $t['amount_atomic'] ) ? gmp_init( $t['amount_atomic'], 10 ) : gmp_init( 0 );
		$counts = $t['commitment_ok'] && ! $t['locked'] && ! $t['in_pool'] && null !== $t['confirmations'] && (int) $t['confirmations'] >= $mc;
		$c = $counts ? $amt : gmp_init( 0 );
		if ( '' === $t['txid'] ) { $bound = gmp_add( $bound, $c ); continue; }
		if ( ! isset( $max_by[ $t['txid'] ] ) || gmp_cmp( $c, $max_by[ $t['txid'] ] ) > 0 ) { $max_by[ $t['txid'] ] = $c; }
	}
	foreach ( $max_by as $v ) { $bound = gmp_add( $bound, $v ); }
	if ( gmp_cmp( gmp_init( $sum['received_pico'], 10 ), $bound ) > 0 ) { $fuzz_ok = false; break; }
	$counter++;
}
ok( "fuzz: confirmed credit never exceeds per-txid max committed total ($counter cases)", $fuzz_ok );

// ── double_spend_seen: a flagged tx is NEVER credited toward settlement (held pending) ──
$ds = XmrPay_Util::summarize_payments( array( row( 'x', 100, array( 'double_spend_seen' => true ) ) ), '100', '0', 1 );
ok( 'double_spend_seen tx is not paid (held pending)', $ds['paid'] === false && $ds['received_pico'] === '0' && $ds['pending_pico'] === '100', verdict_str( $ds ) );
// the SAME tx without the flag settles normally (proves the flag is what blocks it)
$ok = XmrPay_Util::summarize_payments( array( row( 'x', 100 ) ), '100', '0', 1 );
ok( 'same tx without the flag settles', $ok['paid'] === true, verdict_str( $ok ) );
// one good tx + one flagged tx: only the good one counts; total stays short → not paid
$mix = XmrPay_Util::summarize_payments( array( row( 'good', 60 ), row( 'bad', 40, array( 'double_spend_seen' => true ) ) ), '100', '0', 1 );
ok( 'flagged tx excluded from the sum (60 of 100) → not paid', $mix['paid'] === false && $mix['received_pico'] === '60', verdict_str( $mix ) );

echo "\n" . ( $fail ? 'FAILED' : 'ALL GREEN' ) . " — $pass passed, $fail failed\n";
exit( $fail ? 1 : 0 );
