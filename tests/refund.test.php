<?php
/**
 * Refund claim-link address validators — the gates that stop a merchant from sending an
 * irreversible Monero payout to a malformed or typo'd address. Two layers:
 *   XmrPay_Util::is_address_like  — cheap, always-on regex prefilter (no GMP/BCMath)
 *   XmrPay_Scanner::address_valid — real base58 + checksum (offline, needs the crypto exts)
 * The key property: the checksum layer rejects a string the regex CANNOT (right length +
 * charset, wrong checksum — exactly a one-character typo). No WordPress needed:
 *   php tests/refund.test.php
 * (The full claim flow — link binds to one order_key, requested->address_provided->sent —
 * is exercised live in the WP sandbox; those methods are coupled to WooCommerce orders.)
 */

define( 'ABSPATH', __DIR__ . '/' );
if ( ! function_exists( 'wp_parse_url' ) ) { function wp_parse_url( $url, $component = -1 ) { return parse_url( (string) $url, $component ); } }
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/bootstrap.php';

$pass = 0; $fail = 0;
function ok( $name, $cond, $extra = '' ) {
	global $pass, $fail;
	if ( $cond ) { $pass++; echo "PASS  $name\n"; }
	else { $fail++; echo "FAIL  $name" . ( $extra !== '' ? "  — $extra" : '' ) . "\n"; }
}

// a real mainnet address (correct checksum).
$VALID = '45sEohkyWYxAfHy8ekP7B34Bd3qhgrupcQfUQAHvfUWkfgqJhCA4QYLigrBg8G8TE4WggtMGpmjXrbmvepkWLec58KKLkm9';

// ---------- is_address_like (regex prefilter) ----------
ok( 'valid 95-char address passes',        XmrPay_Util::is_address_like( $VALID ) );
ok( 'trims surrounding whitespace',        XmrPay_Util::is_address_like( "  $VALID\n" ) );
ok( '106-char (integrated length) passes', XmrPay_Util::is_address_like( str_repeat( 'A', 106 ) ) );
ok( 'empty -> false',                      ! XmrPay_Util::is_address_like( '' ) );
ok( 'too short -> false',                  ! XmrPay_Util::is_address_like( substr( $VALID, 0, 80 ) ) );
ok( 'too long (100) -> false',             ! XmrPay_Util::is_address_like( str_repeat( 'A', 100 ) ) );
ok( 'non-base58 char 0 -> false',          ! XmrPay_Util::is_address_like( '0' . substr( $VALID, 1 ) ) );
ok( 'non-base58 char O -> false',          ! XmrPay_Util::is_address_like( 'O' . substr( $VALID, 1 ) ) );

// ---------- address_valid (real base58 + checksum, offline) ----------
$sc = new XmrPay_Scanner( 'http://127.0.0.1:18081', 'mainnet', 5 );
ok( 'address_valid: real address -> true',  $sc->address_valid( $VALID ) );
ok( 'address_valid: garbage -> false',      ! $sc->address_valid( 'not-an-address' ) );
ok( 'address_valid: empty -> false',        ! $sc->address_valid( '' ) );

// the linchpin: a one-character typo keeps length + charset (regex passes) but breaks the
// checksum (address_valid catches it). This is what protects an irreversible payout.
$ch     = ( $VALID[20] === 'a' ) ? 'b' : 'a';
$typo   = substr_replace( $VALID, $ch, 20, 1 );
ok( 'typo still LOOKS like an address (regex passes)', XmrPay_Util::is_address_like( $typo ), $typo );
ok( 'typo FAILS the checksum (address_valid catches it)', ! $sc->address_valid( $typo ), $typo );

// ---------- network gate: a wrong-network address (valid checksum) must be rejected ----------
// (sending mainnet XMR to a stagenet-format address would lose the refund — the wallet refuses it).
$STAGENET = '59iRx5JkUsgFg93DWCDsDUBHj8HFnuYLjPPRDapzgfuSYLeb36GKJVHdJ6XAP5K2QJC7TqVdpsthr6JfyMtaSP6bGBPVRCb';
$sc_stage = new XmrPay_Scanner( 'http://127.0.0.1:38081', 'stagenet', 5 );
ok( 'stagenet address has valid checksum + network on a stagenet store', $sc_stage->address_valid( $STAGENET ), $STAGENET );
ok( 'stagenet address REJECTED on a mainnet store (wrong network)',       ! $sc->address_valid( $STAGENET ) );
ok( 'mainnet address REJECTED on a stagenet store (wrong network)',       ! $sc_stage->address_valid( $VALID ) );
ok( 'is_address_like is network-agnostic (both look like addresses)',     XmrPay_Util::is_address_like( $STAGENET ) && XmrPay_Util::is_address_like( $VALID ) );

// ---------- claim-link expiry (PHP mirror of src/refund.js) ----------
ok( 'default claim window is 7 days', XmrPay_Util::DEFAULT_CLAIM_WINDOW_SECS === 604800 );
ok( 'resolve null -> default',  XmrPay_Util::resolve_claim_window( null ) === 604800 );
ok( 'resolve 0 -> never',       XmrPay_Util::resolve_claim_window( 0 ) === 0 );
ok( 'resolve negative -> never', XmrPay_Util::resolve_claim_window( -5 ) === 0 );
ok( 'from_days 7 -> 604800',    XmrPay_Util::claim_window_from_days( 7 ) === 604800 );
ok( 'from_days 0 -> never',     XmrPay_Util::claim_window_from_days( 0 ) === 0 );

// CONFORMANCE VECTORS — identical integers + formula to test/refund.test.js (units arbitrary).
// [status, opened, window, now, expectedExpiresAt, expectedExpired]
$VEC = array(
	array( 'requested',        100, 50, 149,    150, false ),
	array( 'requested',        100, 50, 150,    150, true  ),
	array( 'requested',        100, 50, 151,    150, true  ),
	array( 'requested',        100,  0, 999999,   0, false ),  // never
	array( 'address_provided', 100, 50, 9999,   150, false ),  // captured: link is moot
	array( 'sent',             100, 50, 9999,   150, false ),
);
foreach ( $VEC as $v ) {
	list( $st, $op, $w, $now, $eExp, $eDead ) = $v;
	ok( "vector $st opened=$op win=$w -> expires_at $eExp", XmrPay_Util::claim_expires_at( $op, $w ) === $eExp, (string) XmrPay_Util::claim_expires_at( $op, $w ) );
	ok( "vector $st opened=$op win=$w now=$now -> expired " . ( $eDead ? 'true' : 'false' ), XmrPay_Util::claim_expired( $st, $op, $w, $now ) === $eDead );
}

echo "\n" . ( $fail ? 'FAILED' : 'ALL GREEN' ) . "  $pass passed, $fail failed\n";
exit( $fail ? 1 : 0 );
