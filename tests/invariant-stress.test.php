<?php
/**
 * High-volume PROPERTY/INVARIANT stress — the PHP twin of the lib's test/invariant-stress.test.js.
 * Drives the SAME mulberry32 PRNG (same seed), the SAME invariants on the invoice state machine and
 * the refund claim-link expiry, so the two engines never drift. PHP exposes only
 * XmrPay_Util::to_invoice_state (+ claim_* helpers); the transition map + event taxonomy are an
 * inline mirror of src/state.js (the contract the conformance vectors pin). No WordPress needed:
 *   php tests/invariant-stress.test.php
 *   OPS=2000000 SEED=0xC0FFEE php tests/invariant-stress.test.php   (matched soak vs the JS twin)
 */

define( 'ABSPATH', __DIR__ . '/' );
if ( ! function_exists( 'wp_parse_url' ) ) { function wp_parse_url( $url, $component = -1 ) { return parse_url( (string) $url, $component ); } }
require_once __DIR__ . '/bootstrap.php';

$pass = 0; $fail = 0; $first_fail = null;
function inv( $name, $cond, $ctx = '' ) {
	global $pass, $fail, $first_fail;
	if ( $cond ) { $pass++; return true; }
	$fail++;
	if ( null === $first_fail ) { $first_fail = $name . ( '' !== $ctx ? "  — $ctx" : '' ); }
	return false;
}

// ── seeded PRNG: mulberry32, the SAME algorithm as the JS twin (32-bit uint math). ──
$PRNG_STATE = 0;
function mulberry32_seed( $seed ) { global $PRNG_STATE; $PRNG_STATE = $seed & 0xFFFFFFFF; }
function u32( $x ) { return $x & 0xFFFFFFFF; }
function imul32( $a, $b ) {
	$a &= 0xFFFFFFFF; $b &= 0xFFFFFFFF;
	$ah = ( $a >> 16 ) & 0xFFFF; $al = $a & 0xFFFF;
	return u32( ( $al * $b ) + u32( ( $ah * $b ) << 16 ) );
}
function rnd() {
	global $PRNG_STATE;
	$a = u32( $PRNG_STATE + 0x6D2B79F5 );
	$PRNG_STATE = $a;
	$t = imul32( $a ^ ( $a >> 15 ), 1 | $a );
	$t = u32( ( $t + imul32( $t ^ ( $t >> 7 ), 61 | $t ) ) ^ $t );
	$r = u32( $t ^ ( $t >> 14 ) );
	return $r / 4294967296.0;
}
function pick( $arr ) { return $arr[ (int) floor( rnd() * count( $arr ) ) ]; }
function rand_int( $lo, $hi ) { return $lo + (int) floor( rnd() * ( $hi - $lo + 1 ) ); }

$SEED = getenv( 'SEED' ) !== false ? ( (int) getenv( 'SEED' ) & 0xFFFFFFFF ) : 0x9E3779B9;
$OPS  = getenv( 'OPS' )  !== false ? (int) getenv( 'OPS' ) : 100000;   // suite-fast default; crank via OPS=
mulberry32_seed( $SEED );

$STATES = array( 'created', 'processing', 'settled', 'expired', 'invalid' );
$TERMINAL = array( 'settled', 'expired' );
$TRANSITIONS = array(
	'created'    => array( 'created', 'processing', 'settled', 'expired', 'invalid' ),
	'processing' => array( 'processing', 'settled', 'expired', 'invalid' ),
	'invalid'    => array( 'invalid', 'processing', 'settled', 'expired' ),
	'settled'    => array( 'settled' ),
	'expired'    => array( 'expired' ),
);
function can_transition( $prev, $next, $states, $trans ) {
	if ( ! in_array( $next, $states, true ) ) { return false; }
	if ( null === $prev ) { return 'created' === $next; }
	$allowed = isset( $trans[ $prev ] ) ? $trans[ $prev ] : array();
	return in_array( $next, $allowed, true );
}
function next_events( $prev, $next, $received_increased, $states ) {
	$out = array();
	if ( $prev !== $next && in_array( $next, $states, true ) ) { $out[] = 'invoice.' . $next; }
	if ( $received_increased && 'settled' !== $next && 'expired' !== $next && 'invalid' !== $next ) {
		$out[] = 'payment.received';
	}
	return $out;
}

$STATUSES = array( 'pending', 'mempool', 'unconfirmed', 'partial', 'underpaid', 'locked', 'paid', 'expired', 'invalid' );
$NON_TRANSITION = array( 'node-error', 'node-disagreement', 'replay', 'no-funds', 'bogus', '' );
$NEXT_CANDIDATES = array_merge( $STATES, array( 'whatever', 'CREATED', 'done', '' ) );
$CLAIM_STATUSES = array( 'requested', 'address_provided', 'sent', 'expired', 'unknown', '' );
$RANK = array( 'created' => 0, 'processing' => 1, 'invalid' => 1, 'settled' => 2, 'expired' => 2 );

echo sprintf( "invoice + claim invariant stress — seed=0x%x ops=%d\n", $SEED, $OPS );

// =============================== STATE MACHINE ===============================
for ( $i = 0; $i < $OPS; $i++ ) {
	$prev = rnd() < 0.12 ? null : pick( $STATES );
	$next = pick( $NEXT_CANDIDATES );
	$legal = can_transition( $prev, $next, $STATES, $TRANSITIONS );

	if ( null === $prev ) {
		if ( ! inv( 'born-created', $legal === ( 'created' === $next ), "op#$i null->$next" ) ) { break; }
	}
	if ( 'settled' === $prev ) {
		if ( ! inv( 'settled-terminal', $legal === ( 'settled' === $next ), "op#$i settled->$next" ) ) { break; }
	}
	if ( 'expired' === $prev ) {
		if ( ! inv( 'expired-terminal', $legal === ( 'expired' === $next ), "op#$i expired->$next" ) ) { break; }
	}
	if ( null !== $prev && in_array( $prev, $TERMINAL, true ) && $next !== $prev ) {
		if ( ! inv( 'terminal-never-moves', ! $legal, "op#$i $prev->$next" ) ) { break; }
	}
	if ( ! in_array( $next, $STATES, true ) ) {
		if ( ! inv( 'illegal-target-rejected', ! $legal, "op#$i $prev->$next" ) ) { break; }
	}
	if ( null !== $prev ) {
		if ( ! inv( 'self-transition-legal', can_transition( $prev, $prev, $STATES, $TRANSITIONS ), "op#$i $prev->$prev" ) ) { break; }
	}
	if ( null !== $prev && $legal && $next !== $prev ) {
		if ( ! inv( 'monotone-rank', $RANK[ $next ] >= $RANK[ $prev ], "op#$i $prev->$next" ) ) { break; }
	}

	$status = rnd() < 0.8 ? pick( $STATUSES ) : pick( $NON_TRANSITION );
	$mapped = XmrPay_Util::to_invoice_state( $status );   // '' === JS null

	if ( ! inv( 'status-codomain', '' === $mapped || in_array( $mapped, $STATES, true ), "op#$i status=$status -> $mapped" ) ) { break; }
	if ( in_array( $status, $NON_TRANSITION, true ) ) {
		if ( ! inv( 'verify-only-empty', '' === $mapped, "op#$i status=$status -> $mapped" ) ) { break; }
	}

	if ( '' !== $mapped ) {
		$funds_up = rnd() < 0.5;
		$events   = next_events( $prev, $mapped, $funds_up, $STATES );

		$invoice_events = array_values( array_filter( $events, function ( $e ) { return 0 === strpos( $e, 'invoice.' ); } ) );
		$changed = ( $prev !== $mapped );
		$ok10 = ( $changed && count( $invoice_events ) === 1 && $invoice_events[0] === 'invoice.' . $mapped )
			|| ( ! $changed && count( $invoice_events ) === 0 );
		if ( ! inv( 'one-invoice-event-per-change', $ok10, "op#$i " . var_export( $prev, true ) . "->$mapped " . implode( ',', $events ) ) ) { break; }

		$has_pr   = in_array( 'payment.received', $events, true );
		$finalish = ( 'settled' === $mapped || 'expired' === $mapped || 'invalid' === $mapped );
		if ( ! inv( 'payment.received-rule', $has_pr === ( $funds_up && ! $finalish ), "op#$i $mapped funds_up=" . var_export( $funds_up, true ) ) ) { break; }

		$known = true;
		foreach ( $events as $e ) {
			if ( 'payment.received' !== $e && ! ( 0 === strpos( $e, 'invoice.' ) && in_array( substr( $e, 8 ), $STATES, true ) ) ) { $known = false; break; }
		}
		if ( ! inv( 'events-known-taxonomy', $known, "op#$i " . implode( ',', $events ) ) ) { break; }
	}
}
inv( 'state-machine: terminal set is exactly {settled,expired}', count( $TERMINAL ) === 2 && in_array( 'settled', $TERMINAL, true ) && in_array( 'expired', $TERMINAL, true ) );

// =============================== CLAIM-LINK EXPIRY ===============================
// NOTE: the JS lib works in MILLISECONDS, the PHP plugin in SECONDS, and the default window differs
// by 1000x (7d = 604800000ms vs 604800s). Same FORMULA, same invariants — each test uses its units.
$TIME_MAX = 5000000000;
$DAY = 86400;
for ( $i = 0; $i < $OPS; $i++ ) {
	$status = pick( $CLAIM_STATUSES );
	$opened = rand_int( 0, $TIME_MAX );
	$window = pick( array( null, 0, -1, -$DAY, rand_int( 1, 30 * $DAY ), rand_int( 1, 30 * $DAY ) ) );
	$now    = rand_int( 0, $TIME_MAX );

	$w   = XmrPay_Util::resolve_claim_window( $window );
	$exp = XmrPay_Util::claim_expires_at( $opened, $window );

	if ( ! inv( 'window-nonneg-int', is_int( $w ) && $w >= 0, "op#$i win=" . var_export( $window, true ) . " -> $w" ) ) { break; }
	if ( null === $window && ! inv( 'window-null-default', $w === XmrPay_Util::DEFAULT_CLAIM_WINDOW_SECS, "op#$i -> $w" ) ) { break; }

	if ( 0 === $w ) {
		if ( ! inv( 'never-expires-zero-exp', 0 === $exp, "op#$i exp=$exp" ) ) { break; }
		if ( ! inv( 'never-expires-status', false === XmrPay_Util::claim_expired( $status, $opened, $window, $now ), "op#$i status=$status" ) ) { break; }
	} else {
		if ( ! inv( 'exp-eq-opened-plus-window', $exp === ( $opened + $w ), "op#$i $opened+$w != $exp" ) ) { break; }
	}

	$expired = XmrPay_Util::claim_expired( $status, $opened, $window, $now );

	if ( 'requested' !== $status ) {
		if ( ! inv( 'only-requested-expires', false === $expired, "op#$i status=$status expired=" . var_export( $expired, true ) ) ) { break; }
	} elseif ( $w > 0 ) {
		if ( ! inv( 'requested-boundary', $expired === ( $now >= $exp ), "op#$i now=$now exp=$exp" ) ) { break; }
		$later = $now + rand_int( 0, $TIME_MAX );
		if ( $expired && ! inv( 'monotone-in-time', true === XmrPay_Util::claim_expired( $status, $opened, $window, $later ), "op#$i now=$now later=$later" ) ) { break; }
		$earlier = rand_int( 0, $now );
		if ( ! $expired && ! inv( 'monotone-back', false === XmrPay_Util::claim_expired( $status, $opened, $window, $earlier ), "op#$i now=$now earlier=$earlier" ) ) { break; }
	}
}

echo "\n" . ( $fail ? 'FAILED' : 'ALL GREEN' ) . "  $pass invariant checks passed, $fail failed" .
	( null !== $first_fail ? "\n  first failure: $first_fail  (re-run with SEED=0x" . dechex( $SEED ) . " OPS=$OPS)" : '' ) . "\n";
exit( $fail ? 1 : 0 );
