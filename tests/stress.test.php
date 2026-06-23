<?php
/**
 * High-LOAD / adversarial stress test for the PHP settlement math:
 *   XmrPay_Util::summarize_payments / dedup_outputs / more_creditable / classify_payment.
 *
 * Where aggregation.test.php proves CORRECTNESS on small hand-built cases, this one
 * piles on VOLUME the happy-path suite never sees: thousands of rows per call, very
 * long installment chains that must sum to the price, large numbers of same-output-key
 * duplicates (burning-bug dedup under load), heavy mixes of double_spend_seen + locked
 * + in_pool rows, amounts at the piconero / uint64 precision limits, and — the headline
 * property — ORDER-INDEPENDENCE under volume: shuffle a big row set many times and the
 * verdict + received_pico must be byte-identical every single time.
 *
 * Deterministic: a tiny seeded LCG drives every shuffle/data choice; no rand() in any
 * assertion. Reproducible run to run.
 *
 *   php tests/stress.test.php
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
// a committed, confirmed, unlocked row by default; override any field. (matches aggregation.test.php)
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

/**
 * Deterministic PRNG — a 32-bit LCG (glibc constants). Seed it once; every shuffle and
 * every random data choice in this file flows through it, so the whole run reproduces.
 * NEVER used inside an assertion's expected value — only to BUILD inputs and to SHUFFLE.
 */
$LCG_STATE = 0;
function lcg_seed( $s ) { global $LCG_STATE; $LCG_STATE = $s & 0xFFFFFFFF; }
function lcg_next() { global $LCG_STATE; $LCG_STATE = ( 1103515245 * $LCG_STATE + 12345 ) & 0xFFFFFFFF; return $LCG_STATE; }
function lcg_int( $lo, $hi ) { if ( $hi <= $lo ) { return $lo; } return $lo + ( lcg_next() % ( $hi - $lo + 1 ) ); }
// Fisher–Yates using the seeded LCG. Returns a NEW shuffled array (preserves the input).
function lcg_shuffle( $arr ) {
	$a = array_values( $arr );
	for ( $i = count( $a ) - 1; $i > 0; $i-- ) {
		$j = lcg_int( 0, $i );
		$t = $a[ $i ]; $a[ $i ] = $a[ $j ]; $a[ $j ] = $t;
	}
	return $a;
}

lcg_seed( 20260621 );

/**
 * Independent (re-implemented, NOT borrowed from the SUT) upper bound on what
 * summarize_payments may legitimately credit, given the dedup key rules:
 *   - dedup key = 'k:'+out_key when out_key is non-empty, else 't:'+txid when txid is
 *     non-empty, else the row stands alone (an own anonymous bucket).
 *   - within a key, only ONE copy is credited; the most that copy can contribute is the
 *     MAX committed+unlocked+not-double-spend+not-pool+confirmed amount among the copies
 *     (anything that fails those gates contributes 0 to confirmed credit).
 * This is deliberately a *ceiling*, computed a different way than the SUT, so "credit
 * never exceeds the per-output committed total" is a real cross-check, not a tautology.
 */
function credit_ceiling( $rows, $min_conf ) {
	$min_conf = max( 0, (int) $min_conf );
	$max_by   = array();   // key => GMP max creditable amount
	$anon     = gmp_init( 0 );
	$i        = 0;
	foreach ( $rows as $t ) {
		if ( ! is_array( $t ) ) { $i++; continue; }
		$raw = isset( $t['amount_atomic'] ) ? (string) $t['amount_atomic'] : '0';
		$amt = preg_match( '/^\d+$/', $raw ) ? gmp_init( $raw, 10 ) : gmp_init( 0 );
		$confs   = ( isset( $t['confirmations'] ) && null !== $t['confirmations'] ) ? (int) $t['confirmations'] : null;
		$counts  = ! empty( $t['commitment_ok'] )
			&& empty( $t['locked'] )
			&& empty( $t['double_spend_seen'] )
			&& empty( $t['in_pool'] )
			&& null !== $confs && $confs >= $min_conf;
		$c = $counts ? $amt : gmp_init( 0 );

		$ok = ( isset( $t['out_key'] ) && '' !== (string) $t['out_key'] );
		$tx = ( isset( $t['txid'] ) && '' !== (string) $t['txid'] );
		if ( $ok )      { $k = 'k:' . (string) $t['out_key']; }
		elseif ( $tx )  { $k = 't:' . (string) $t['txid']; }
		else            { $anon = gmp_add( $anon, $c ); $i++; continue; }

		if ( ! isset( $max_by[ $k ] ) || gmp_cmp( $c, $max_by[ $k ] ) > 0 ) { $max_by[ $k ] = $c; }
		$i++;
	}
	$bound = $anon;
	foreach ( $max_by as $v ) { $bound = gmp_add( $bound, $v ); }
	return $bound;
}

// ════════════════════════════════════════════════════════════════════════════
// 1. LONG INSTALLMENT CHAIN that SUMS EXACTLY to the price (thousands of rows).
//    Each tx pays a few pico; together they hit the price to the piconero.
// ════════════════════════════════════════════════════════════════════════════
$N = 5000;
$rows = array();
$sum  = 0;
for ( $i = 0; $i < $N; $i++ ) {
	$amt   = lcg_int( 1, 50 );
	$sum  += $amt;
	$rows[] = row( 'inst_' . $i, $amt, array( 'out_key' => 'K_' . $i ) );  // all distinct outputs
}
$price = (string) $sum;
$r = XmrPay_Util::summarize_payments( $rows, $price, '0', 1 );
ok( "installment chain of $N distinct txs sums EXACTLY to price ($price pico) → paid",
	$r['paid'] === true && $r['received_pico'] === $price, verdict_str( $r ) );

// one pico short of the price across the same chain → NOT paid, status partial, off by exactly 1.
$rows2 = $rows;
// shave one pico off the first row that has > 1 pico so the chain falls 1 short.
foreach ( $rows2 as $idx => $rr ) {
	if ( (int) $rr['amount_atomic'] > 1 ) { $rows2[ $idx ]['amount_atomic'] = (string) ( (int) $rr['amount_atomic'] - 1 ); break; }
}
$r = XmrPay_Util::summarize_payments( $rows2, $price, '0', 1 );
ok( "same chain ONE pico short → not paid, shortfall exactly 1",
	$r['paid'] === false && $r['status'] === 'partial' && $r['shortfall_pico'] === '1', verdict_str( $r ) );

// ════════════════════════════════════════════════════════════════════════════
// 2. MANY same-output-key DUPLICATES (burning-bug dedup under load).
//    DUP copies of ONE output key, spread across DUP distinct txids, each claiming
//    the full price. On-chain only one is spendable → must be credited exactly ONCE.
// ════════════════════════════════════════════════════════════════════════════
$DUP   = 4000;
$price = '1000000';
$rows  = array();
for ( $i = 0; $i < $DUP; $i++ ) {
	$rows[] = row( 'burn_' . $i, $price, array( 'out_key' => 'P_SHARED' ) );
}
$r = XmrPay_Util::summarize_payments( $rows, $price, '0', 1 );
ok( "$DUP copies of one shared output key (distinct txids) credited ONCE → paid exactly the price",
	$r['paid'] === true && $r['received_pico'] === $price, verdict_str( $r ) );

// the exploit form: a 2× order must NOT settle on those same-key copies (only 1× is real).
$r = XmrPay_Util::summarize_payments( $rows, (string) gmp_strval( gmp_mul( gmp_init( $price ), 2 ) ), '0', 1 );
ok( "$DUP same-key copies do NOT settle a 2× order (no false-paid under load)",
	$r['paid'] === false && $r['received_pico'] === $price, verdict_str( $r ) );

// burning-bug under load, but the credited copy must be the CONSERVATIVE (smallest) one:
// many same-key copies disagreeing on amount → smaller wins, never the inflated claim.
$rows = array();
for ( $i = 0; $i < $DUP; $i++ ) {
	$amt    = ( $i === 1234 ) ? '7' : (string) lcg_int( 8, 9999999 );   // exactly one tiny "7" copy
	$rows[] = row( 'b' . $i, $amt, array( 'out_key' => 'P_ONE' ) );
}
$r = XmrPay_Util::summarize_payments( $rows, '1000000', '0', 1 );
ok( "same-key copies disagreeing on amount → smallest (7) credited, never the inflated claim",
	$r['received_pico'] === '7' && $r['paid'] === false, verdict_str( $r ) );

// ════════════════════════════════════════════════════════════════════════════
// 3. HEAVY MIX of double_spend_seen + locked + in_pool + good, at volume.
//    Build a big set where exactly the "good" rows sum to the price, and every other
//    category is present in bulk and must contribute 0 to confirmed credit.
// ════════════════════════════════════════════════════════════════════════════
$rows = array();
$good_sum = 0;
$tag = 0;
for ( $i = 0; $i < 1500; $i++ ) {
	$a = lcg_int( 1, 100 ); $good_sum += $a;
	$rows[] = row( 'g' . ( $tag++ ), $a, array( 'out_key' => 'OK_' . $i ) );                 // good
	$rows[] = row( 'd' . ( $tag++ ), lcg_int( 1, 1e6 ), array( 'out_key' => 'DS_' . $i, 'double_spend_seen' => true ) ); // poisoned
	$rows[] = row( 'l' . ( $tag++ ), lcg_int( 1, 1e6 ), array( 'out_key' => 'LK_' . $i, 'locked' => true ) );            // time-locked
	$rows[] = row( 'p' . ( $tag++ ), lcg_int( 1, 1e6 ), array( 'out_key' => 'PL_' . $i, 'in_pool' => true, 'confirmations' => null ) ); // mempool
}
$price = (string) $good_sum;
$r = XmrPay_Util::summarize_payments( $rows, $price, '0', 1 );
ok( "heavy mix (6000 rows): only the good rows credited, sums to price → paid",
	$r['paid'] === true && $r['received_pico'] === $price, verdict_str( $r ) );
// none of the poisoned categories leaked into confirmed credit:
ok( "heavy mix: double_spend + in_pool sit in pending, locked sits in locked, none in received",
	gmp_cmp( gmp_init( $r['received_pico'] ), gmp_init( $price ) ) === 0
		&& gmp_cmp( gmp_init( $r['locked_pico'] ), 0 ) > 0
		&& gmp_cmp( gmp_init( $r['pending_pico'] ), 0 ) > 0,
	'locked=' . $r['locked_pico'] . ' pending=' . $r['pending_pico'] . ' recv=' . $r['received_pico'] );
// and the credit ceiling (independent) is respected:
ok( "heavy mix: received_pico ≤ independent credit ceiling",
	gmp_cmp( gmp_init( $r['received_pico'] ), credit_ceiling( $rows, 1 ) ) <= 0,
	$r['received_pico'] . ' vs ceiling ' . gmp_strval( credit_ceiling( $rows, 1 ) ) );

// ════════════════════════════════════════════════════════════════════════════
// 4. AMOUNTS NEAR THE PRECISION / uint64 LIMITS.
//    1 piconero, the full uint64 supply ceiling, and sums that straddle int64.
//    (PHP int overflows past ~9.2M XMR; the math is GMP, so this must stay exact.)
// ════════════════════════════════════════════════════════════════════════════
$U64 = '18446744073709551615';   // 2^64 - 1, the largest a node could report per output
$r = XmrPay_Util::summarize_payments( array( row( 'huge', $U64, array( 'out_key' => 'H' ) ) ), $U64, '0', 1 );
ok( "uint64-max single output settles its own uint64-max price exactly (GMP, no overflow)",
	$r['paid'] === true && $r['received_pico'] === $U64 && $r['overpaid_pico'] === '0', verdict_str( $r ) );

// two uint64-max outputs sum past int64 cleanly.
$twoU64 = gmp_strval( gmp_mul( gmp_init( $U64 ), 2 ) );
$r = XmrPay_Util::summarize_payments( array(
	row( 'h1', $U64, array( 'out_key' => 'H1' ) ),
	row( 'h2', $U64, array( 'out_key' => 'H2' ) ),
), $twoU64, '0', 1 );
ok( "two uint64-max outputs sum to 2×uint64 (well past int64) exactly → paid",
	$r['paid'] === true && $r['received_pico'] === $twoU64, verdict_str( $r ) );

// 1-piconero precision: a price of 1 pico is paid by 1 pico, NOT by 0.
$r = XmrPay_Util::summarize_payments( array( row( 'one', 1, array( 'out_key' => 'ONE' ) ) ), '1', '0', 1 );
ok( "1-piconero price settled by exactly 1 piconero", $r['paid'] === true && $r['received_pico'] === '1', verdict_str( $r ) );
// a 1-pico order is NEVER settled on a zeroed/uncommitted output, even at the floor.
$r = XmrPay_Util::summarize_payments( array( row( 'z', 1, array( 'out_key' => 'Z', 'commitment_ok' => false ) ) ), '1', '0', 1 );
ok( "1-piconero price NOT settled by an uncommitted output (no false-paid at the floor)",
	$r['paid'] === false && $r['received_pico'] === '0', verdict_str( $r ) );

// ════════════════════════════════════════════════════════════════════════════
// 5. ORDER-INDEPENDENCE UNDER VOLUME — the headline property.
//    Build ONE large adversarial row set (good + poisoned + duplicates + anon rows),
//    fix a price, then SHUFFLE it many times with the seeded LCG and assert the verdict
//    + received_pico are byte-identical on every shuffle. (dedup + more_creditable must
//    be a total order; row arrival order must never move the money.)
// ════════════════════════════════════════════════════════════════════════════
$rows = array();
$tag = 0;
// a block of distinct good outputs
for ( $i = 0; $i < 800; $i++ ) { $rows[] = row( 'G' . ( $tag++ ), lcg_int( 1, 200 ), array( 'out_key' => 'GK_' . $i ) ); }
// same-key duplicate clusters that disagree on EVERY tie-break field (lock, pool, confs, amount, commitment)
for ( $i = 0; $i < 300; $i++ ) {
	$key = 'CLUST_' . $i;
	$rows[] = row( 'c' . ( $tag++ ), lcg_int( 1, 1000 ), array( 'out_key' => $key, 'confirmations' => lcg_int( 0, 30 ) ) );
	$rows[] = row( 'c' . ( $tag++ ), lcg_int( 1, 1000 ), array( 'out_key' => $key, 'locked' => (bool) lcg_int( 0, 1 ) ) );
	$rows[] = row( 'c' . ( $tag++ ), lcg_int( 1, 1000 ), array( 'out_key' => $key, 'in_pool' => (bool) lcg_int( 0, 1 ), 'confirmations' => null ) );
	$rows[] = row( 'c' . ( $tag++ ), lcg_int( 1, 1000 ), array( 'out_key' => $key, 'commitment_ok' => (bool) lcg_int( 0, 1 ) ) );
	$rows[] = row( 'c' . ( $tag++ ), lcg_int( 1, 1000 ), array( 'out_key' => $key, 'double_spend_seen' => (bool) lcg_int( 0, 1 ) ) );
}
// txid-keyed duplicates (no out_key) that also disagree
for ( $i = 0; $i < 300; $i++ ) {
	$tx = 'TX_' . $i;
	$rows[] = row( $tx, lcg_int( 1, 1000 ), array( 'locked' => (bool) lcg_int( 0, 1 ) ) );
	$rows[] = row( $tx, lcg_int( 1, 1000 ), array( 'confirmations' => lcg_int( 0, 30 ) ) );
	$rows[] = row( $tx, lcg_int( 1, 1000 ), array( 'in_pool' => (bool) lcg_int( 0, 1 ), 'confirmations' => null ) );
}
// anonymous rows (no out_key, no txid) — never deduped, each stands alone
for ( $i = 0; $i < 200; $i++ ) { $rows[] = row( '', lcg_int( 1, 50 ) ); }
// a scatter of malformed amounts that must read as 0 and never crash the sum
for ( $i = 0; $i < 200; $i++ ) {
	$bad = array( '', '-5', 'abc', '0x10', '1.5', ' 9 ', null )[ lcg_int( 0, 6 ) ];
	$rows[] = row( 'mal_' . $i, $bad, array( 'out_key' => 'MAL_' . $i ) );
}

$total_rows = count( $rows );
$price = '500000';     // a fixed mid-range price for the shuffle invariant
$ref   = XmrPay_Util::summarize_payments( $rows, $price, '0', 2 );
$ref_v = verdict_str( $ref );

$SHUFFLES   = 400;
$order_ok   = true;
$recv_ok    = true;
$ceiling    = credit_ceiling( $rows, 2 );
$ceiling_ok = gmp_cmp( gmp_init( $ref['received_pico'] ), $ceiling ) <= 0;
for ( $s = 0; $s < $SHUFFLES; $s++ ) {
	$shuf = lcg_shuffle( $rows );
	$rr   = XmrPay_Util::summarize_payments( $shuf, $price, '0', 2 );
	if ( verdict_str( $rr ) !== $ref_v )            { $order_ok = false; break; }
	if ( $rr['received_pico'] !== $ref['received_pico'] ) { $recv_ok = false; break; }
	if ( gmp_cmp( gmp_init( $rr['received_pico'] ), $ceiling ) > 0 ) { $ceiling_ok = false; break; }
}
ok( "order-independence under volume: $SHUFFLES shuffles of $total_rows rows → identical verdict", $order_ok, $ref_v );
ok( "order-independence under volume: received_pico identical across all $SHUFFLES shuffles", $recv_ok, $ref['received_pico'] );
ok( "under volume: received_pico never exceeds the independent per-output credit ceiling", $ceiling_ok,
	$ref['received_pico'] . ' vs ' . gmp_strval( $ceiling ) );

// the same big set, settled at price 1 (everything that CAN settle, does): still order-independent.
$ref1   = verdict_str( XmrPay_Util::summarize_payments( $rows, '1', '0', 2 ) );
$ord1   = true;
for ( $s = 0; $s < 100; $s++ ) {
	if ( verdict_str( XmrPay_Util::summarize_payments( lcg_shuffle( $rows ), '1', '0', 2 ) ) !== $ref1 ) { $ord1 = false; break; }
}
ok( 'order-independence under volume at price=1 (100 shuffles)', $ord1, $ref1 );

// ════════════════════════════════════════════════════════════════════════════
// 6. RANDOMIZED VOLUME FUZZ — many big calls, each cross-checked against the
//    independent credit ceiling AND against a forced re-shuffle. Catches a false-paid
//    or a credit that exceeds the per-output committed total on ANY generated set.
// ════════════════════════════════════════════════════════════════════════════
$fuzz_ok      = true;
$no_false     = true;
$shuffle_ok   = true;
$cases        = 0;
$keys         = array( 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', '' );  // '' out_key → falls back to txid
for ( $iter = 0; $iter < 600; $iter++ ) {
	$n    = lcg_int( 200, 1200 );
	$set  = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$ok_key = $keys[ lcg_int( 0, count( $keys ) - 1 ) ];
		$over   = array(
			'confirmations'     => lcg_int( 0, 1 ) ? lcg_int( 0, 20 ) : null,
			'in_pool'           => (bool) lcg_int( 0, 1 ),
			'locked'            => (bool) lcg_int( 0, 1 ),
			'commitment_ok'     => (bool) lcg_int( 0, 1 ),
			'double_spend_seen' => (bool) lcg_int( 0, 4 ) === 0 ? false : (bool) ( lcg_int( 0, 5 ) === 0 ),
		);
		if ( '' !== $ok_key ) { $over['out_key'] = $ok_key . lcg_int( 0, 40 ); }
		$txid  = lcg_int( 0, 1 ) ? 't' . lcg_int( 0, 40 ) : '';
		$set[] = row( $txid, lcg_int( 0, 100000 ), $over );
	}
	$mc  = lcg_int( 1, 5 );
	$exp = (string) lcg_int( 1, 2000000 );
	$res = XmrPay_Util::summarize_payments( $set, $exp, '0', $mc );

	// (a) credit never exceeds the independent per-output ceiling.
	if ( gmp_cmp( gmp_init( $res['received_pico'] ), credit_ceiling( $set, $mc ) ) > 0 ) { $fuzz_ok = false; break; }
	// (b) NO FALSE-PAID: paid=true ⇒ confirmed credit ≥ the (clamped) threshold ≥ ... and never on 0.
	if ( $res['paid'] ) {
		$thr = gmp_sub( gmp_init( $exp ), gmp_init( 0 ) );  // tol=0 here → threshold == expected
		if ( gmp_cmp( gmp_init( $res['received_pico'] ), $thr ) < 0 ) { $no_false = false; break; }
		if ( gmp_cmp( gmp_init( $res['received_pico'] ), 0 ) <= 0 )   { $no_false = false; break; }
	}
	// (c) re-shuffling THIS set must not change the verdict.
	if ( verdict_str( XmrPay_Util::summarize_payments( lcg_shuffle( $set ), $exp, '0', $mc ) ) !== verdict_str( $res ) ) {
		$shuffle_ok = false; break;
	}
	$cases++;
}
ok( "fuzz: credit never exceeds per-output committed ceiling ($cases big cases)", $fuzz_ok );
ok( "fuzz: no false-paid — every paid verdict has confirmed credit ≥ threshold and > 0", $no_false );
ok( "fuzz: each generated set is order-independent under one re-shuffle", $shuffle_ok );

// ════════════════════════════════════════════════════════════════════════════
// 7. classify_payment under the same precision / tolerance pressure.
//    (the per-tx classifier the lib mirrors — exercised at the uint64 edge and with
//    an absurd tolerance that must NEVER let a zero payment settle.)
// ════════════════════════════════════════════════════════════════════════════
$c = XmrPay_Util::classify_payment( $U64, $U64, '0', 1, 10, false, false );
ok( 'classify: uint64-max received vs uint64-max expected → paid, no overpaid', $c['paid'] === true && $c['overpaid_pico'] === '0', $c['status'] );

$c = XmrPay_Util::classify_payment( '100', '0', '100', 1, 10, false, false );
ok( 'classify: absurd tolerance + zero received → pending, never paid', $c['paid'] === false && $c['status'] === 'pending', $c['status'] );

// clamp pins the threshold at exactly 1 pico (tol 999999 of a 1000000 price), so 1 pico
// is the floor that DOES settle — but 0 never can. This is the clamp's whole job: it can
// lower the bar to 1 piconero, never to 0.
$c1 = XmrPay_Util::classify_payment( '1000000', '1', '999999', 1, 10, false, false );
ok( 'classify: clamp pins threshold at 1 pico → 1 pico settles at the floor', $c1['paid'] === true, $c1['status'] );
$c0 = XmrPay_Util::classify_payment( '1000000', '0', '999999', 1, 10, false, false );
ok( 'classify: same clamp, 0 received → still pending (clamp never reaches 0)', $c0['paid'] === false && $c0['status'] === 'pending', $c0['status'] );

// classify is order-free by nature, but check it agrees with itself across a volume sweep:
// for every (exp, rec) drawn, paid ⇔ rec ≥ max(exp - clamp(tol), 1) AND confs ≥ min_conf AND !locked.
$classify_ok = true;
for ( $i = 0; $i < 5000; $i++ ) {
	$exp    = lcg_int( 1, 1000000 );
	$rec    = lcg_int( 0, 1100000 );
	$tol    = lcg_int( 0, 1200000 );
	$mc     = lcg_int( 1, 6 );
	$confs  = lcg_int( 0, 10 );
	$locked = (bool) lcg_int( 0, 1 );
	$res    = XmrPay_Util::classify_payment( (string) $exp, (string) $rec, (string) $tol, $mc, $confs, false, $locked );
	$clamp  = min( $tol, $exp - 1 );           // tolerance can never reach the price
	$thr    = $exp - $clamp;                    // ≥ 1
	$expect_paid = ( $rec > 0 ) && ! $locked && ( $rec >= $thr ) && ( $confs >= $mc );
	if ( $res['paid'] !== $expect_paid ) { $classify_ok = false; break; }
	if ( $res['paid'] && $rec <= 0 ) { $classify_ok = false; break; }   // never paid on nothing
}
ok( 'classify: 5000-case sweep matches the clamped-threshold spec (no false-paid, never on 0)', $classify_ok );

echo "\n" . ( $fail ? 'FAILED' : 'ALL GREEN' ) . " — $pass passed, $fail failed\n";
exit( $fail ? 1 : 0 );
