<?php
/**
 * Standalone tests for XmrPay_Util — the exact money math + webhook HMAC.
 * No WordPress needed:  php tests/util.test.php
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
function eq( $name, $got, $want ) { ok( $name, $got === $want, "got '" . var_export( $got, true ) . "' want '" . var_export( $want, true ) . "'" ); }

// ---------- fmt: canonical XMR string ----------
eq( 'fmt integer',            XmrPay_Util::fmt( 1 ),            '1' );
eq( 'fmt trims zeros',        XmrPay_Util::fmt( 0.0500 ),       '0.05' );
eq( 'fmt zero',               XmrPay_Util::fmt( 0 ),            '0' );
eq( 'fmt negative -> 0',      XmrPay_Util::fmt( -5 ),           '0' );
eq( 'fmt 1 piconero',         XmrPay_Util::fmt( 0.000000000001 ), '0.000000000001' );
eq( 'fmt caps at 12 dec',     XmrPay_Util::fmt( 0.1234567890123 ), '0.123456789012' );
eq( 'fmt rounds at pico',     XmrPay_Util::fmt( 0.0000000000005 ), '0.000000000001' );
eq( 'fmt big amount',         XmrPay_Util::fmt( 12345.6789 ),   '12345.6789' );
// idempotent: formatting a formatted value is stable
$a = XmrPay_Util::fmt( 0.1 / 3 );
eq( 'fmt idempotent',         XmrPay_Util::fmt( $a ),           $a );
ok( 'fmt is always <=12 dec', (function(){ for($i=0;$i<200;$i++){ $v=mt_rand(1,9999999)/mt_rand(1,7919); $s=XmrPay_Util::fmt($v); $dot=strpos($s,'.'); if($dot!==false && (strlen($s)-$dot-1)>12) return false; } return true; })() );

// ---------- from_total: discounts/shipping/tax already in the total ----------
// $37.80 final (after a coupon + shipping + tax) at 150 USD/XMR
eq( 'total -> xmr',           XmrPay_Util::from_total( 37.80, 150 ), '0.252' );
eq( 'xmr-native passthrough', XmrPay_Util::from_total( 0.05, 1 ),    '0.05' );
eq( 'rate 0 -> 0 (guard)',    XmrPay_Util::from_total( 50, 0 ),      '0' );
eq( 'free order total 0',     XmrPay_Util::from_total( 0, 150 ),     '0' );
// the buyer pays exactly what the agent expects: same string, no drift
$total = 19.99; $rate = 142.37;
$amt = XmrPay_Util::from_total( $total, $rate );
eq( 'amount is re-fmt stable', XmrPay_Util::fmt( $amt ), $amt );
ok( 'amount never exceeds the fiat value', (float) $amt <= ( $total / $rate ) + 1e-12 );
// fuzz: random carts + rates always yield a clean, bounded XMR string
ok( 'fuzz totals/rates clean', (function(){
	for ( $i = 0; $i < 500; $i++ ) {
		$t = mt_rand( 1, 500000 ) / 100;           // $0.01 .. $5000
		$r = mt_rand( 50, 50000 ) / 100;           // 0.50 .. 500 per XMR
		$s = XmrPay_Util::from_total( $t, $r );
		if ( ! is_string( $s ) || $s === '' ) return false;
		if ( ! preg_match( '/^\d+(\.\d{1,12})?$/', $s ) ) return false;   // clean decimal, <=12
	}
	return true;
} )() );

// ---------- verify_sig: webhook HMAC (agent signs, plugin verifies) ----------
$secret = 'whsec_test_xmrpay';
$body   = '{"event":"order.paid","order_id":42,"amount_xmr":"0.05","received_xmr":"0.051"}';
// this is exactly how the Node lib (src/webhook.js) signs it
$good   = 'sha256=' . hash_hmac( 'sha256', $body, $secret );
ok( 'verify accepts a valid signature', XmrPay_Util::verify_sig( $body, $good, $secret ) === true );
ok( 'verify rejects a tampered body',   XmrPay_Util::verify_sig( $body . ' ', $good, $secret ) === false );
ok( 'verify rejects wrong secret',      XmrPay_Util::verify_sig( $body, $good, 'nope' ) === false );
ok( 'verify rejects missing signature', XmrPay_Util::verify_sig( $body, '', $secret ) === false );
ok( 'verify rejects null signature',    XmrPay_Util::verify_sig( $body, null, $secret ) === false );
ok( 'empty secret = reject (fail closed)', XmrPay_Util::verify_sig( $body, 'anything', '' ) === false );
ok( 'null secret = reject (fail closed)',  XmrPay_Util::verify_sig( $body, 'anything', null ) === false );
ok( 'verify is prefix-strict',          XmrPay_Util::verify_sig( $body, hash_hmac( 'sha256', $body, $secret ), $secret ) === false ); // no "sha256=" prefix

// ---------- event_fresh: webhook replay window (event_ts in ms) ----------
$now = 1700000000; // arbitrary "now" in seconds
ok( 'event_fresh: current stamp accepted',          XmrPay_Util::event_fresh( $now * 1000, $now ) === true );
ok( 'event_fresh: 1h old accepted',                 XmrPay_Util::event_fresh( ( $now - 3600 ) * 1000, $now ) === true );
ok( 'event_fresh: 2d old rejected',                 XmrPay_Util::event_fresh( ( $now - 2 * 86400 ) * 1000, $now ) === false );
ok( 'event_fresh: absent stamp = accept (old agents)', XmrPay_Util::event_fresh( null, $now ) === true );
ok( 'event_fresh: garbage stamp = accept',          XmrPay_Util::event_fresh( 'xx', $now ) === true );

// ---------- test_amount_allowed: never price a live store ----------
ok( 'test_amount: stagenet + matching url → allowed', XmrPay_Util::test_amount_allowed( 'stagenet', 'http://127.0.0.1:8788', 'http://127.0.0.1:8788/' ) === true );
ok( 'test_amount: testnet + matching url → allowed',  XmrPay_Util::test_amount_allowed( 'testnet', 'http://127.0.0.1:8788', 'http://127.0.0.1:8788' ) === true );
ok( 'test_amount: mainnet → blocked',                 XmrPay_Util::test_amount_allowed( 'mainnet', 'http://127.0.0.1:8788', 'http://127.0.0.1:8788' ) === false );
ok( 'test_amount: empty network → blocked',           XmrPay_Util::test_amount_allowed( '', 'http://x', 'http://x' ) === false );
ok( 'test_amount: stale flag (url changed) → blocked', XmrPay_Util::test_amount_allowed( 'stagenet', 'http://127.0.0.1:8788', 'http://node.example:18081' ) === false );
ok( 'test_amount: no tested url → blocked',           XmrPay_Util::test_amount_allowed( 'stagenet', '', 'http://x' ) === false );

// ---------- same_origin: keep the order key on-site ----------
ok( 'same_origin: same host → true',                 XmrPay_Util::same_origin( 'https://shop.test/thanks', 'https://shop.test' ) === true );
ok( 'same_origin: relative path → true',             XmrPay_Util::same_origin( '/thanks?o=1', 'https://shop.test' ) === true );
ok( 'same_origin: other host → false',               XmrPay_Util::same_origin( 'https://evil.test/x', 'https://shop.test' ) === false );
ok( 'same_origin: protocol-relative off-site → false', XmrPay_Util::same_origin( '//evil.test/x', 'https://shop.test' ) === false );
ok( 'same_origin: case-insensitive host → true',     XmrPay_Util::same_origin( 'https://SHOP.test/x', 'https://shop.test' ) === true );

// ---------- pico helpers + amount-nonce (proof mode) ----------
eq( 'xmr_to_pico exact',         XmrPay_Util::xmr_to_pico( 0.05 ),        50000000000 );
eq( 'xmr_to_pico 1 pico',        XmrPay_Util::xmr_to_pico( 0.000000000001 ), 1 );
eq( 'xmr_to_pico zero/neg',      XmrPay_Util::xmr_to_pico( -1 ),          0 );
eq( 'pico_to_string roundtrip',  XmrPay_Util::pico_to_string( 50000000000 ), '0.05' );
eq( 'pico_to_string integer',    XmrPay_Util::pico_to_string( 1000000000000 ), '1' );
eq( 'pico_to_string zero',       XmrPay_Util::pico_to_string( 0 ),        '0' );
// above signed int64 (~9.2M XMR) must NOT truncate — GMP, exact (hardening fix)
eq( 'pico_to_string uint64-max', XmrPay_Util::pico_to_string( '18446744073709551615' ), '18446744.073709551615' );
eq( 'pico_to_string > int64',    XmrPay_Util::pico_to_string( '10000000000000000000' ), '10000000' );
// nonce: lands in (base, base + 10^6) piconero, never equals the base, exact string
ok( 'nonce_amount adds 1..999999 pico, exact', (function () {
	$base = XmrPay_Util::xmr_to_pico( '0.05' );          // 50000000000
	for ( $i = 0; $i < 500; $i++ ) {
		$s = XmrPay_Util::nonce_amount( '0.05', 6 );
		$p = XmrPay_Util::xmr_to_pico( $s );
		if ( $p <= $base || $p >= $base + 1000000 ) { return false; }
		if ( XmrPay_Util::pico_to_string( $p ) !== $s ) { return false; }   // canonical, no float tail
		$dot = strpos( $s, '.' ); if ( $dot !== false && ( strlen( $s ) - $dot - 1 ) > 12 ) { return false; }
	}
	return true;
} )() );
ok( 'nonce_amount is unique across orders (no collision in 1000 draws)', (function () {
	$seen = array();
	for ( $i = 0; $i < 1000; $i++ ) { $seen[ XmrPay_Util::nonce_amount( '0.05', 6 ) ] = true; }
	return count( $seen ) > 950;   // ~1000 distinct from a 999999-wide space
} )() );
eq( 'nonce_amount zero base → 0',  XmrPay_Util::nonce_amount( 0, 6 ),     '0' );
ok( 'nonce_amount clamps bad digits', XmrPay_Util::nonce_amount( '0.05', 99 ) !== '0' );

// ---------- classify_payment: the money decision in exact piconero ----------
$cp = function ( $exp, $rec, $tol, $minc, $conf, $pool, $locked ) {
	return XmrPay_Util::classify_payment( $exp, $rec, $tol, $minc, $conf, $pool, $locked );
};
// exact pay, enough confs → paid, no overpay
$r = $cp( '50000000000', '50000000000', '0', 1, 1, false, false );
ok( 'classify: exact + 1 conf → paid', $r['status'] === 'paid' && $r['paid'] === true && $r['overpaid_pico'] === '0' );
// 1 piconero short → underpaid (the boundary that matters)
$r = $cp( '50000000000', '49999999999', '0', 1, 10, false, false );
ok( 'classify: 1 pico short → underpaid', $r['status'] === 'underpaid' && $r['paid'] === false && $r['shortfall_pico'] === '1' );
// 1 piconero over → paid + overpaid 1
$r = $cp( '50000000000', '50000000001', '0', 1, 10, false, false );
ok( 'classify: 1 pico over → paid + overpaid 1', $r['status'] === 'paid' && $r['overpaid_pico'] === '1' );
// no funds → pending
$r = $cp( '50000000000', '0', '0', 1, 0, false, false );
ok( 'classify: zero received → pending', $r['status'] === 'pending' && $r['paid'] === false );
// enough amount but not enough confs, in pool → mempool
$r = $cp( '50000000000', '50000000000', '0', 2, 0, true, false );
ok( 'classify: paid amount, 0/2 conf, in pool → mempool', $r['status'] === 'mempool' && $r['paid'] === false );
// enough amount, not enough confs, not in pool → unconfirmed
$r = $cp( '50000000000', '50000000000', '0', 2, 1, false, false );
ok( 'classify: paid amount, 1/2 conf → unconfirmed', $r['status'] === 'unconfirmed' );
// time-locked → locked even with full amount + confs
$r = $cp( '50000000000', '50000000000', '0', 1, 100, false, true );
ok( 'classify: full amount but locked → locked (never paid)', $r['status'] === 'locked' && $r['paid'] === false );
// tolerance: received exactly expected - tolerance → paid
$r = $cp( '50000000000', '49999999000', '1000', 1, 1, false, false );
ok( 'classify: within tolerance → paid', $r['status'] === 'paid' && $r['paid'] === true );
// tolerance: 1 pico below the tolerant threshold → underpaid
$r = $cp( '50000000000', '49999998999', '1000', 1, 1, false, false );
ok( 'classify: 1 pico below tolerant threshold → underpaid', $r['status'] === 'underpaid' );
// tolerance CLAMP: absurd tolerance must NOT let a zero payment settle
$r = $cp( '50000000000', '0', '999999999999', 1, 100, false, false );
ok( 'classify: zero received + absurd tolerance → still pending (no false pay)', $r['status'] === 'pending' && $r['paid'] === false );
// tolerance CLAMP: threshold floors at 1 pico, so 1 pico settles under absurd tolerance (merchant config)
$r = $cp( '50000000000', '1', '999999999999', 1, 1, false, false );
ok( 'classify: tolerance clamps to leave threshold >= 1 pico', $r['status'] === 'paid' );
// uint64-large amounts (beyond PHP int) handled exactly via gmp
$big = '18446744073709551615'; // 2^64 - 1
$r = $cp( $big, $big, '0', 1, 1, false, false );
ok( 'classify: uint64-max exact → paid (gmp, no overflow)', $r['status'] === 'paid' && $r['overpaid_pico'] === '0' );
$r = $cp( $big, '18446744073709551614', '0', 1, 1, false, false );
ok( 'classify: uint64-max minus 1 → underpaid, shortfall 1', $r['status'] === 'underpaid' && $r['shortfall_pico'] === '1' );
// nonce_amount output is comparable in pico and classifies correctly against its base+nonce
$nb = XmrPay_Util::xmr_to_pico( '0.05' );
$ns = XmrPay_Util::nonce_amount( '0.05' );
$np = XmrPay_Util::xmr_to_pico( $ns );
$r  = $cp( (string) $np, (string) $np, '0', 1, 1, false, false );
ok( 'classify: a nonced order amount pays exactly', $r['status'] === 'paid' && $np > $nb );

echo "\n" . ( $fail ? "FAIL" : "ALL GREEN" ) . " — $pass passed, $fail failed\n";
exit( $fail ? 1 : 0 );
