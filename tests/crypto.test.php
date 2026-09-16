<?php
/**
 * OFFLINE crypto known-answer + adversarial tests for the WP-native scanner.
 * Unlike scanner.test.php (which needs a live node + real on-chain vectors), this
 * runs with NO network — it locks the primitives the keyless scanner is built on
 * (Keccak-256, Monero base58) and fuzzes the tx parser so hostile input can never
 * crash it or produce a false "this output is ours".
 *
 *   php tests/crypto.test.php
 */

define( 'ABSPATH', __DIR__ . '/' );   // satisfy the includes' direct-access guard
if ( ! function_exists( 'wp_parse_url' ) ) { function wp_parse_url( $url, $component = -1 ) { return parse_url( (string) $url, $component ); } }
function wp_safe_remote_post( $url, $args ) { $r = $GLOBALS['MOCK_TX_RESPONSES'][ $url ] ?? ( substr( $url, -9 ) === '/json_rpc' ? ( $GLOBALS['MOCK_RPC_RESPONSE'] ?? array() ) : $GLOBALS['MOCK_TX_RESPONSE'] ); return array( 'response' => array( 'code' => 200 ), 'body' => json_encode( $r ) ); }
function wp_remote_retrieve_response_code( $res ) { return $res['response']['code']; }
function wp_remote_retrieve_body( $res ) { return $res['body']; }
function is_wp_error( $res ) { return false; }
require_once __DIR__ . '/bootstrap.php';

$pass = 0; $fail = 0;
function ok( $n, $c, $x = '' ) { global $pass, $fail; if ( $c ) { $pass++; echo "PASS  $n\n"; } else { $fail++; echo "FAIL  $n" . ( $x !== '' ? "  — $x" : '' ) . "\n"; } }

// ───────── Keccak-256 known-answer vectors (the FIPS-202 Keccak, not SHA3) ─────────
// guards the `ord()` fix: `(int) $char` silently cast every non-numeric pad byte to 0,
// which corrupted the rate-block padding and would have produced wrong hashes.
ok( 'keccak256("")', \kornrunner\Keccak::hash( '', 256 ) === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470' );
ok( 'keccak256("abc")', \kornrunner\Keccak::hash( 'abc', 256 ) === '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45' );
ok( 'keccak256("The quick brown fox...")',
	\kornrunner\Keccak::hash( 'The quick brown fox jumps over the lazy dog', 256 )
	=== '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15' );
// multi-block input (>136-byte rate) exercises the padding byte path repeatedly
$big = \kornrunner\Keccak::hash( str_repeat( 'a', 1000 ), 256 );
ok( 'keccak256(1000×"a") is deterministic + well-formed', strlen( $big ) === 64 && ctype_xdigit( $big )
	&& $big === \kornrunner\Keccak::hash( str_repeat( 'a', 1000 ), 256 ) );

// ───────── Monero base58 round-trip + invalid-char rejection ─────────
$b58 = new \MoneroIntegrations\MoneroPhp\base58();
// a real mainnet address must decode to 69 bytes (netbyte 0x12 + 32 spend + 32 view + 4 csum)
$MAIN = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
$hex  = $b58->decode( $MAIN );
ok( 'base58 mainnet addr → 69 bytes, netbyte 0x12', strlen( $hex ) === 138 && substr( $hex, 0, 2 ) === '12' );
ok( 'base58 round-trip: encode(decode(addr)) === addr', $b58->encode( $hex ) === $MAIN );
// a stagenet address round-trips too (different netbyte, same codec)
$STAGE = '5BEiTonHrFFgGSRAQTknCsEU9jRtGXEVBbv9bZSHCybmUT6aoA2V9M98rLFW2rfzyw5ayituBVETeG9Zkw3AAsyqE4T7N2n';
ok( 'base58 round-trip: stagenet addr', $b58->encode( $b58->decode( $STAGE ) ) === $STAGE );
// the `=== false` fix: a full-length block carrying a char OUTSIDE the alphabet must throw,
// not silently decode (strpos returns false, and `false < 0` was false → it slipped through).
$threw = false;
try { $b58->decode( '1111111111O' ); } catch ( \Throwable $e ) { $threw = true; } // 'O' is not in the base58 alphabet
ok( 'base58 rejects an out-of-alphabet char (=== false fix)', $threw );

// ───────── detect_in_tx fuzz: hostile tx input never crashes, never false-positives ─────────
// detect_in_tx is fully offline (parses the tx + derives locally; no node call), so we can
// hammer it with garbage. a dummy node URL is never contacted.
$VIEW = '3b6765f2072e11438aaa22ae9168adf304c414d8da5de504dcdb46e397a6f604'; // disposable stagenet view-only key
$ADDR = '5BEiTonHrFFgGSRAQTknCsEU9jRtGXEVBbv9bZSHCybmUT6aoA2V9M98rLFW2rfzyw5ayituBVETeG9Zkw3AAsyqE4T7N2n';
$sc   = new XmrPay_Scanner( 'http://127.0.0.1:1', 'stagenet' );

$rand_bytes = function ( $n ) { $a = array(); for ( $i = 0; $i < $n; $i++ ) { $a[] = mt_rand( 0, 255 ); } return $a; };

$err = 0; set_error_handler( function () use ( &$err ) { $err++; return false; } );
$crashed = false; $falsepos = false;
mt_srand( 1337 ); // deterministic fuzz
for ( $iter = 0; $iter < 1500; $iter++ ) {
	// build a hostile tx with random extra, random vout shapes, random ecdh/outpk
	$nout = mt_rand( 0, 4 );
	$vout = array();
	for ( $j = 0; $j < $nout; $j++ ) {
		$shape = mt_rand( 0, 3 );
		if ( 0 === $shape ) { $vout[] = array( 'target' => array( 'key' => bin2hex( pack( 'C*', ...$rand_bytes( 32 ) ) ) ) ); }
		elseif ( 1 === $shape ) { $vout[] = array( 'target' => array( 'tagged_key' => array( 'key' => bin2hex( pack( 'C*', ...$rand_bytes( 32 ) ) ) ) ) ); }
		elseif ( 2 === $shape ) { $vout[] = array( 'target' => array() ); }             // missing key
		else { $vout[] = array(); }                                                      // missing target
	}
	$tx = array(
		'extra'          => $rand_bytes( mt_rand( 0, 40 ) ),
		'vout'           => $vout,
		'rct_signatures' => array(
			'ecdhInfo' => array( array( 'amount' => bin2hex( pack( 'C*', ...$rand_bytes( 8 ) ) ) ) ),
			'outPk'    => array( bin2hex( pack( 'C*', ...$rand_bytes( 32 ) ) ) ),
		),
	);
	try {
		$r = $sc->detect_in_tx( $tx, $ADDR, $VIEW );
		if ( null !== $r ) { $falsepos = true; }   // random data must NEVER be detected as ours
	} catch ( \Throwable $e ) { $crashed = true; break; }
}

// the new DoS guard: a tx claiming a huge output count must bail, not loop forever
$huge = array( 'extra' => array(), 'vout' => array_fill( 0, 300, array( 'target' => array( 'key' => str_repeat( 'a', 64 ) ) ) ), 'rct_signatures' => array() );
$huge_r = null; try { $huge_r = $sc->detect_in_tx( $huge, $ADDR, $VIEW ); } catch ( \Throwable $e ) { $crashed = true; }
restore_error_handler();

ok( 'fuzz: 1500 hostile txs never threw', ! $crashed );
ok( 'fuzz: hostile txs never raised a PHP warning/notice', 0 === $err, "warnings=$err" );
ok( 'fuzz: random data is NEVER detected as a payment (no false-positive)', ! $falsepos );
ok( 'fuzz: >256-output tx bails via the DoS guard → null', null === $huge_r );

// A node that omits, substitutes, or fails to decode a requested tx must not let
// the block scanner checkpoint past that payment.
$a = str_repeat( 'a', 64 ); $b = str_repeat( 'b', 64 ); $c = str_repeat( 'c', 64 );
$row = function ( $hash ) { return array( 'tx_hash' => $hash, 'as_json' => '{"extra":[],"vout":[]}', 'block_height' => 100 ); };
$GLOBALS['MOCK_TX_RESPONSE'] = array( 'txs' => array( $row( $a ), $row( $b ) ) );
ok( 'complete tx batch accepted', count( $sc->fetch_txs( array( $a, $b ) ) ) === 2 );
$GLOBALS['MOCK_TX_RESPONSE'] = array( 'txs' => array( $row( $a ) ) );
ok( 'missing tx rejects the whole block batch', null === $sc->fetch_txs( array( $a, $b ) ) );
$GLOBALS['MOCK_TX_RESPONSE'] = array( 'txs' => array( $row( $a ), $row( $c ) ) );
ok( 'substituted tx rejects the whole block batch', null === $sc->fetch_txs( array( $a, $b ) ) );
$bad = $row( $b ); $bad['as_json'] = '{';
$GLOBALS['MOCK_TX_RESPONSE'] = array( 'txs' => array( $row( $a ), $bad ) );
ok( 'undecodable tx rejects the whole block batch', null === $sc->fetch_txs( array( $a, $b ) ) );
$bad['as_json'] = '{}';
$GLOBALS['MOCK_TX_RESPONSE'] = array( 'txs' => array( $row( $a ), $bad ) );
ok( 'tx without output structure rejects the whole block batch', null === $sc->fetch_txs( array( $a, $b ) ) );

$nodes = array( 'http://127.0.0.1:2', 'http://127.0.0.1:3' );
$multi = new XmrPay_Scanner( $nodes, 'stagenet' );
$GLOBALS['MOCK_TX_RESPONSES'] = array(
    $nodes[0] . '/get_transactions' => array( 'txs' => array( $row( $a ) ) ),
    $nodes[1] . '/get_transactions' => array( 'txs' => array( $row( $a ) ) ),
);
ok( 'two agreeing nodes accept a tx', count( $multi->fetch_txs( array( $a ) ) ) === 1 );
$with_extra = $row( $a ); $with_extra['as_json'] = '{"extra":[],"vout":[],"unused_daemon_field":true}';
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[1] . '/get_transactions' ] = array( 'txs' => array( $with_extra ) );
ok( 'irrelevant daemon fields do not pause verification', count( $multi->fetch_txs( array( $a ) ) ) === 1 );
$changed_output = $row( $a ); $changed_output['as_json'] = '{"extra":[],"vout":[{"amount":1}]}';
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[1] . '/get_transactions' ] = array( 'txs' => array( $changed_output ) );
ok( 'payment evidence disagreement pauses verification', null === $multi->fetch_txs( array( $a ) ) );
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[1] . '/get_transactions' ] = array( 'txs' => array( $row( $a ) ) );
$early = $row( $a ); $early['block_height'] = 1;
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[0] . '/get_transactions' ] = array( 'txs' => array( $early ) );
ok( 'height disagreement cannot confirm early', null === $multi->fetch_txs( array( $a ) ) );
unset( $GLOBALS['MOCK_TX_RESPONSES'][ $nodes[1] . '/get_transactions' ] );
$GLOBALS['MOCK_TX_RESPONSE'] = array();
ok( 'missing node pauses multi-node verification', null === $multi->fetch_txs( array( $a ) ) );
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[0] . '/json_rpc' ] = array( 'result' => array( 'tx_hashes' => array( $a ) ) );
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[1] . '/json_rpc' ] = array( 'result' => array( 'tx_hashes' => array() ) );
$scan = $multi->scan_all( $ADDR, $VIEW, 100, 100, array( 'tip' => 110 ) );
ok( 'block hash disagreement cannot advance scan', $scan['scanned_to'] === 99 );
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[1] . '/json_rpc' ] = array( 'result' => array( 'tx_hashes' => array( $a ) ) );
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[0] . '/get_transactions' ] = array( 'txs' => array( $row( $a ) ) );
$GLOBALS['MOCK_TX_RESPONSES'][ $nodes[1] . '/get_transactions' ] = array( 'txs' => array( $row( $a ) ) );
$scan = $multi->scan_all( $ADDR, $VIEW, 100, 100, array( 'tip' => 110 ) );
ok( 'matching block and tx advance scan', $scan['scanned_to'] === 100 );
unset( $GLOBALS['MOCK_TX_RESPONSES'] );

$GLOBALS['MOCK_TX_RESPONSE'] = array( 'txs' => array( $early ) );
$GLOBALS['MOCK_RPC_RESPONSE'] = array( 'result' => array( 'tx_hashes' => array( $a ) ) );
$scan = $sc->scan_all( $ADDR, $VIEW, 100, 100, array( 'tip' => 110 ) );
ok( 'tx outside claimed block cannot advance scan', $scan['scanned_to'] === 99 && count( $scan['matches'] ) === 0 );

$later = new class( 'http://127.0.0.1:1', 'stagenet' ) extends XmrPay_Scanner {
    public function detect_in_tx( $tx, $address, $view_key ) {
        return $tx['_txid'] === str_repeat( 'b', 64 )
            ? array( 'amount_atomic' => '100', 'output_index' => 0, 'commitment_ok' => true ) : null;
    }
};
$GLOBALS['MOCK_TX_RESPONSE'] = array( 'txs' => array( $early, $row( $b ) ) );
$GLOBALS['MOCK_RPC_RESPONSE'] = array( 'result' => array( 'tx_hashes' => array( $a, $b ) ) );
$scan = $later->scan_all( $ADDR, $VIEW, 100, 100, array( 'tip' => 110 ) );
ok( 'later valid payment remains visible without checkpointing incomplete block',
    $scan['scanned_to'] === 99 && count( $scan['matches'] ) === 1 && $scan['matches'][0]['txid'] === $b );
$scan = $later->scan( $ADDR, $VIEW, 100, 100, array( 'tip' => 110 ) );
ok( 'first-match scan also reaches later valid payment', ! empty( $scan['found'] ) && $scan['txid'] === $b );

echo "\n" . ( 0 === $fail ? 'ALL GREEN' : 'FAILED' ) . " — $pass passed, $fail failed\n";
exit( 0 === $fail ? 0 : 1 );
