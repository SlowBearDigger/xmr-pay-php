<?php
/**
 * Canonical invoice-state mirror tests for XmrPay_Util::to_invoice_state.
 * These VECTORS are the byte-for-byte mirror of the lib's test/state.test.js, so the PHP
 * scanner and the JS agent can never drift on what state an order is in. JS returns null
 * for verify-only outcomes; PHP returns ''. No WordPress needed:  php tests/state.test.php
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

// status -> canonical state (MIRROR of test/state.test.js VECTORS)
$VECTORS = array(
	'pending'     => 'created',
	'mempool'     => 'processing',
	'unconfirmed' => 'processing',
	'partial'     => 'processing',
	'underpaid'   => 'processing',
	'locked'      => 'processing',
	'paid'        => 'settled',
	'expired'     => 'expired',
	'invalid'     => 'invalid',
);
foreach ( $VECTORS as $status => $state ) {
	eq( "status \"$status\" -> $state", XmrPay_Util::to_invoice_state( $status ), $state );
}

// verify-ONLY outcomes are NOT invoice transitions (JS null === PHP '')
foreach ( array( 'node-error', 'node-disagreement', 'replay', 'no-funds', 'bogus', '' ) as $s ) {
	eq( "verify-only \"$s\" -> '' (no transition)", XmrPay_Util::to_invoice_state( $s ), '' );
}

// the five canonical states are exactly the codomain of the settlement statuses
$states = array_values( $VECTORS );
sort( $states );
$states = array_values( array_unique( $states ) );
ok( 'codomain is created/processing/settled/expired (+invalid)',
	$states === array( 'created', 'expired', 'invalid', 'processing', 'settled' ),
	implode( ',', $states ) );

echo "\n" . ( $fail ? 'FAILED' : 'ALL GREEN' ) . "  $pass passed, $fail failed\n";
exit( $fail ? 1 : 0 );
