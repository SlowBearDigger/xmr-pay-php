<?php

require_once __DIR__ . '/bootstrap.php';

$envPath = getenv( 'XMRPAY_GATEWAY_ENV' );
if ( false === $envPath || '' === $envPath ) {
	$envPath = dirname( __DIR__, 3 ) . '/secrets/gateway.env';
}
if ( ! is_file( $envPath ) ) {
	echo "SKIP  node-auth - private gateway environment not found\n";
	exit( 0 );
}
$env = parse_ini_file( $envPath, false, INI_SCANNER_RAW );

$pass = 0;
$fail = 0;
function auth_ok( $condition, $name, $extra = '' ) {
	global $pass, $fail;
	if ( $condition ) {
		$pass++;
		echo "PASS  {$name}\n";
		return;
	}
	$fail++;
	echo "FAIL  {$name}" . ( '' !== $extra ? "  {$extra}" : '' ) . "\n";
}

function auth_node( $url, $auth, $username, $password ) {
	return array(
		'url'                 => $url,
		'auth'                => $auth,
		'username'            => $username,
		'password'            => $password,
		'allow_insecure_http' => true,
	);
}

$basicA = auth_node( 'http://127.0.0.1:38091', 'basic', $env['BASIC_A_USER'], $env['BASIC_A_PASSWORD'] );
$basicB = auth_node( 'http://127.0.0.1:38092', 'basic', $env['BASIC_B_USER'], $env['BASIC_B_PASSWORD'] );
$digestA = auth_node( 'http://127.0.0.1:38093', 'digest', $env['DIGEST_A_USER'], $env['DIGEST_A_PASSWORD'] );
$digestB = auth_node( 'http://127.0.0.1:38094', 'digest', $env['DIGEST_B_USER'], $env['DIGEST_B_PASSWORD'] );

$scanner = new XmrPay\Scanner( array( $basicA ), 'stagenet', 8 );
$height = $scanner->tip_height();
auth_ok( is_int( $height ) && $height > 0, 'Basic credentials reach the node' );

$wrong = $basicA;
$wrong['password'] = 'deliberately-wrong';
$scanner = new XmrPay\Scanner( array( $wrong ), 'stagenet', 8 );
auth_ok( null === $scanner->tip_height(), 'wrong Basic password rejected' );
$error = $scanner->last_node_error();
auth_ok( 'authentication-rejected' === $error['code'], 'Basic rejection has a specific code' );
auth_ok( false === strpos( json_encode( $error ), 'deliberately-wrong' ), 'Basic error redacts password' );

$scanner = new XmrPay\Scanner( array( $digestA ), 'stagenet', 8 );
$height = $scanner->tip_height();
auth_ok( is_int( $height ) && $height > 0, 'Digest credentials reach the node', json_encode( $scanner->last_node_error() ) );

$wrong = $digestA;
$wrong['password'] = 'deliberately-wrong';
$scanner = new XmrPay\Scanner( array( $wrong ), 'stagenet', 8 );
auth_ok( null === $scanner->tip_height(), 'wrong Digest password rejected' );
auth_ok( 'authentication-rejected' === $scanner->last_node_error()['code'], 'Digest rejection has a specific code', json_encode( $scanner->last_node_error() ) );

$swapped = $basicB;
$swapped['username'] = $basicA['username'];
$swapped['password'] = $basicA['password'];
$scanner = new XmrPay\Scanner( array( $swapped ), 'stagenet', 8 );
auth_ok( null === $scanner->tip_height(), 'node A credentials fail against node B' );

$swappedDigest = $digestB;
$swappedDigest['username'] = $digestA['username'];
$swappedDigest['password'] = $digestA['password'];
$scanner = new XmrPay\Scanner( array( $swappedDigest ), 'stagenet', 8 );
auth_ok( null === $scanner->tip_height(), 'Digest node A credentials fail against node B' );

$wrongPrimary = $basicA;
$wrongPrimary['password'] = 'primary-is-deliberately-wrong';
$scanner = new XmrPay\Scanner( array( $wrongPrimary, $basicB ), 'stagenet', 8 );
$height = $scanner->tip_height();
auth_ok( is_int( $height ) && $height > 0, 'failed primary rotates to secondary credentials' );
$error = $scanner->last_node_error();
auth_ok( 0 === $error['node_index'] && 'authentication-rejected' === $error['code'], 'primary failure remains available as a warning' );
auth_ok( false === strpos( json_encode( $error ), $basicB['password'] ), 'failover warning redacts secondary password' );

$scanner = new XmrPay\Scanner( array(
	array( 'url' => 'http://127.0.0.1:38098', 'auth' => 'none' ),
	$basicB,
), 'stagenet', 8 );
$knownStagenetTxid = '25fc8ec8d330846d071bafcccb5de07b0c54e3b20c85f9de67d953f92853871d';
$txs = $scanner->fetch_txs( array( $knownStagenetTxid ) );
auth_ok( is_array( $txs ), 'POST with wrong-schema primary fails over to authenticated secondary', json_encode( $scanner->last_node_error() ) );
$error = $scanner->last_node_error();
auth_ok( 0 === $error['node_index'] && 'malformed-response' === $error['code'], 'POST schema failure remains available as a warning', json_encode( $error ) );

$wrongDigest = $digestA;
$wrongDigest['password'] = 'digest-primary-is-deliberately-wrong';
$scanner = new XmrPay\Scanner( array( $wrongDigest, $basicB ), 'stagenet', 8 );
$txs = $scanner->fetch_txs( array( $knownStagenetTxid ) );
auth_ok( is_array( $txs ) && isset( $txs[0] ), 'POST fails over from rejected Digest primary to Basic secondary' );
$error = $scanner->last_node_error();
auth_ok( 0 === $error['node_index'] && 'authentication-rejected' === $error['code'], 'mixed-auth failover preserves primary warning' );

$scanner = new XmrPay\Scanner( array(
	array( 'url' => 'http://127.0.0.1:38096', 'auth' => 'none' ),
	$basicB,
), 'stagenet', 8 );
$info = $scanner->node_info();
auth_ok( ! empty( $info['ok'] ) && 'stagenet' === $info['nettype'], 'node_info gets network from authenticated secondary' );

$rollout = dirname( dirname( $envPath ) );
$collectorLog = $rollout . '/gateway/logs/collector.log';
$before = is_file( $collectorLog ) ? count( file( $collectorLog ) ) : 0;
$redirect = auth_node( 'http://127.0.0.1:38097', 'basic', $env['BASIC_A_USER'], $env['BASIC_A_PASSWORD'] );
$scanner = new XmrPay\Scanner( array( $redirect ), 'stagenet', 8 );
auth_ok( null === $scanner->tip_height(), 'authenticated redirect rejected' );
usleep( 100000 );
$after = is_file( $collectorLog ) ? count( file( $collectorLog ) ) : 0;
auth_ok( $before === $after, 'redirect does not forward credentials' );
auth_ok( 'redirect-rejected' === $scanner->last_node_error()['code'], 'redirect has a specific code' );

$before = is_file( $collectorLog ) ? count( file( $collectorLog ) ) : 0;
$scanner = new XmrPay\Scanner( array( $redirect ), 'stagenet', 8 );
auth_ok( null === $scanner->fetch_txs( array( $knownStagenetTxid ) ), 'authenticated POST redirect rejected' );
usleep( 100000 );
$after = is_file( $collectorLog ) ? count( file( $collectorLog ) ) : 0;
auth_ok( $before === $after, 'POST redirect does not forward credentials' );

$scanner = new XmrPay\Scanner( array(
	array( 'url' => 'http://127.0.0.1:38095', 'auth' => 'none' ),
), 'stagenet', 1 );
$started = microtime( true );
auth_ok( null === $scanner->tip_height(), 'configured timeout stops a delayed node' );
auth_ok( microtime( true ) - $started < 3.0, 'timeout remains bounded' );
auth_ok( 'timeout' === $scanner->last_node_error()['code'], 'timeout has a specific code', json_encode( $scanner->last_node_error() ) );

define( 'XMRPAY_TESTING_NO_CURL', true );
$scanner = new XmrPay\Scanner( array( $basicA ), 'stagenet', 8 );
$height = $scanner->tip_height();
auth_ok( is_int( $height ) && $height > 0, 'Basic works through the stream fallback' );

$before = is_file( $collectorLog ) ? count( file( $collectorLog ) ) : 0;
$scanner = new XmrPay\Scanner( array( $redirect ), 'stagenet', 8 );
auth_ok( null === $scanner->tip_height(), 'stream fallback rejects authenticated redirect' );
usleep( 100000 );
$after = is_file( $collectorLog ) ? count( file( $collectorLog ) ) : 0;
auth_ok( $before === $after, 'stream fallback does not forward credentials' );

$before = is_file( $collectorLog ) ? count( file( $collectorLog ) ) : 0;
$scanner = new XmrPay\Scanner( array( $redirect ), 'stagenet', 8 );
auth_ok( null === $scanner->fetch_txs( array( $knownStagenetTxid ) ), 'stream fallback rejects authenticated POST redirect' );
usleep( 100000 );
$after = is_file( $collectorLog ) ? count( file( $collectorLog ) ) : 0;
auth_ok( $before === $after, 'stream POST redirect does not forward credentials' );

$scanner = new XmrPay\Scanner( array( $digestA, $basicA ), 'stagenet', 8 );
$txs = $scanner->fetch_txs( array( $knownStagenetTxid ) );
auth_ok( is_array( $txs ) && isset( $txs[0] ), 'Digest unsupported falls over to stream Basic' );
auth_ok( 'digest-unsupported' === $scanner->last_node_error()['code'], 'no-cURL mixed failover preserves Digest warning' );

$scanner = new XmrPay\Scanner( array( 'http://127.0.0.1:38098' ), 'stagenet', 8 );
auth_ok( null === $scanner->tip_height(), 'response without height is rejected' );
auth_ok( 'malformed-response' === $scanner->last_node_error()['code'], 'missing height has a specific code' );

$scanner = new XmrPay\Scanner( array( $digestA ), 'stagenet', 8 );
auth_ok( null === $scanner->tip_height(), 'Digest fails closed without cURL' );
auth_ok( 'digest-unsupported' === $scanner->last_node_error()['code'], 'Digest without cURL has a specific code' );

echo "\n" . ( $fail ? "FAILED ({$fail})" : 'ALL GREEN' ) . "  {$pass} passed, {$fail} failed\n";
exit( $fail ? 1 : 0 );
