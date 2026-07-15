<?php

require_once dirname( __DIR__ ) . '/src/NodeConfig.php';

use XmrPay\NodeConfig;

$pass = 0;
$fail = 0;

function ok( $condition, $name ) {
	global $pass, $fail;
	if ( $condition ) {
		$pass++;
		echo "PASS  {$name}\n";
		return;
	}
	$fail++;
	echo "FAIL  {$name}\n";
}

function rejects( $value, $reason, $name ) {
	try {
		NodeConfig::normalizeList( $value );
		ok( false, $name );
	} catch ( InvalidArgumentException $e ) {
		ok( $reason === $e->getMessage(), $name );
	}
}

$legacy = NodeConfig::normalizeList( "https://node-a.example\nhttp://127.0.0.1:38090, https://node-b.example/" );
ok( 3 === count( $legacy ), 'legacy comma and newline list' );
ok( 'none' === $legacy[0]['auth'] && '' === $legacy[0]['username'] && '' === $legacy[0]['password'], 'legacy rows are unauthenticated' );
ok( 'https://node-b.example' === $legacy[2]['url'], 'trailing slash normalized' );

$digest = NodeConfig::normalizeList( array(
	array(
		'url'                 => 'http://127.0.0.1:38093',
		'auth'                => 'DIGEST',
		'username'            => 'digest-a',
		'password'            => 'secret-a',
		'allow_insecure_http' => true,
	),
) );
ok( 'digest' === $digest[0]['auth'], 'digest preserved' );
ok( 'digest-a' === $digest[0]['username'] && 'secret-a' === $digest[0]['password'], 'credentials remain bound to their row' );
ok( false === strpos( json_encode( NodeConfig::publicList( $digest ) ), 'secret-a' ), 'public list redacts password' );
ok( false === strpos( json_encode( NodeConfig::publicList( $digest ) ), 'digest-a' ), 'public list redacts username' );

$json = NodeConfig::normalizeList( json_encode( array(
	array( 'url' => 'https://node-a.example', 'auth' => 'basic', 'username' => 'a', 'password' => 'one' ),
	array( 'url' => 'https://node-b.example', 'auth' => 'basic', 'username' => 'b', 'password' => 'two' ),
) ) );
ok( 'one' === $json[0]['password'] && 'two' === $json[1]['password'], 'JSON credentials stay isolated' );

$none = NodeConfig::normalizeList( array(
	'url'      => 'https://node.example',
	'auth'     => 'none',
	'username' => 'must-clear',
	'password' => 'must-clear',
) );
ok( '' === $none[0]['username'] && '' === $none[0]['password'], 'auth none clears credentials' );

rejects( 'ftp://node.example', 'invalid-scheme', 'invalid scheme rejected' );
rejects( 'https://user:pass@node.example', 'embedded-credentials', 'embedded credentials rejected' );
rejects( array( array( 'url' => 'https://node.example', 'auth' => 'basic', 'username' => 'a' ) ), 'missing-credentials', 'missing password rejected' );
rejects( array( array( 'url' => 'https://node.example', 'auth' => 'bearer', 'username' => 'a', 'password' => 'b' ) ), 'invalid-auth', 'invalid auth rejected' );
rejects( array( array( 'url' => 'https://node.example', 'auth' => 'basic', 'username' => 'shop:eu', 'password' => 'b' ) ), 'invalid-username', 'colon in authenticated username rejected' );
rejects( array( array( 'url' => 'http://127.0.0.1:38091', 'auth' => 'basic', 'username' => 'a', 'password' => 'b' ) ), 'insecure-http-auth', 'authenticated HTTP requires opt in' );
rejects( '[not-json]', 'invalid-json', 'invalid JSON rejected' );
rejects( '', 'empty-node-list', 'empty list rejected' );
rejects( 'https://node.example%40evil.example', 'invalid-url', 'percent-encoded host rejected' );
rejects( 'https://::1:18081', 'invalid-url', 'unbracketed IPv6 host rejected' );
rejects( 'https:/node.example', 'invalid-url', 'single-slash scheme rejected' );
rejects( 'https:node.example', 'invalid-url', 'slashless scheme rejected' );
rejects( array( array( 'wrong-key' => 'https://node.example' ) ), 'invalid-node', 'row without node keys rejected' );

$v6 = NodeConfig::normalizeList( 'https://[::1]:18081' );
ok( 'https://[::1]:18081' === $v6[0]['url'], 'bracketed IPv6 host accepted' );

echo "\n" . ( $fail ? "FAILED ({$fail})" : 'ALL GREEN' ) . "  {$pass} passed, {$fail} failed\n";
exit( $fail ? 1 : 0 );
