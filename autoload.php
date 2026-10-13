<?php
// Optional entry point for a vendored copy or archive without Composer.
// Composer consumers should keep using vendor/autoload.php.

if ( ! defined( 'XMRPAY_PORTABLE_AUTOLOAD' ) ) {
	define( 'XMRPAY_PORTABLE_AUTOLOAD', true );
	$root = __DIR__;
	require_once $root . '/third-party/monero/base58.php';
	require_once $root . '/third-party/monero/Varint.php';
	require_once $root . '/third-party/monero/Keccak.php';
	require_once $root . '/third-party/monero/ed25519.php';
	require_once $root . '/third-party/monero/Cryptonote.php';
	spl_autoload_register( function ( $class ) use ( $root ) {
		$prefix = 'XmrPay\\';
		if ( strpos( $class, $prefix ) !== 0 ) { return; }
		$file = $root . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
		if ( is_file( $file ) ) { require_once $file; }
	} );
}
