<?php
// Verify incoming Monero payments against configured daemon nodes.

namespace XmrPay;

use MoneroIntegrations\MoneroPhp\Cryptonote;

class Scanner {

	const H_POINT = '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94';

	private $nodes;
	private $cn;
	private $http_timeout;
	private $network;
	private $last_node_error = array( 'code' => 'none', 'node_index' => null, 'url' => '' );

	public function __construct( $node, $network = 'mainnet', $http_timeout = 20 ) {

		$this->nodes        = NodeConfig::normalizeList( $node );
		$this->http_timeout = (int) $http_timeout;
		$this->network      = in_array( $network, array( 'mainnet', 'stagenet', 'testnet' ), true ) ? $network : 'mainnet';
		$this->cn           = new Cryptonote( $this->network );
	}

	private function node_rpc( $path, $body, $required_array_key = null ) {

		$this->reset_node_error();
		foreach ( $this->nodes as $index => $node ) {
			$r = $this->node_rpc_one( $node, $index, $path, $body );
			if ( null === $r ) { continue; }
			if ( null === $required_array_key || ( isset( $r[ $required_array_key ] ) && is_array( $r[ $required_array_key ] ) ) ) {
				return $r;
			}
			$this->set_node_error( 'malformed-response', $index, $node );
		}
		return null;
	}

	private function node_rpc_one( $node, $index, $path, $body ) {
		$url     = $node['url'] . $path;
		$payload = function_exists( 'wp_json_encode' ) ? wp_json_encode( $body ) : json_encode( $body );
		if ( 'none' === $node['auth'] && function_exists( 'wp_safe_remote_post' ) ) {
			$res = wp_safe_remote_post( $url, array(
				'timeout'             => $this->http_timeout,
				'redirection'         => 0,
				'headers'             => array( 'Content-Type' => 'application/json' ),
				'body'                => $payload,
				'limit_response_size' => 4 * 1024 * 1024,
			) );
			if ( is_wp_error( $res ) ) {
				$this->set_node_error( $this->wp_error_code( $res ), $index, $node );
				return null;
			}
			$code = (int) wp_remote_retrieve_response_code( $res );
			if ( $code < 200 || $code >= 300 ) {
				$this->set_node_error( $this->http_error_code( $code ), $index, $node );
				return null;
			}
			$raw = wp_remote_retrieve_body( $res );
			if ( strlen( $raw ) > 4 * 1024 * 1024 ) {
				$this->set_node_error( 'response-too-large', $index, $node );
				return null;
			}
			return $this->decode_response( $raw, $index, $node );
		}

		$raw = $this->http_raw( $url, $payload, $node, $index );
		if ( null === $raw ) { return null; }
		if ( strlen( $raw ) > 4 * 1024 * 1024 ) {
			$this->set_node_error( 'response-too-large', $index, $node );
			return null;
		}
		return $this->decode_response( $raw, $index, $node );
	}

	private function http_raw( $url, $payload, $node, $index ) {
		if ( ! in_array( strtolower( (string) parse_url( $url, PHP_URL_SCHEME ) ), array( 'http', 'https' ), true ) ) {
			$this->set_node_error( 'invalid-scheme', $index, $node );
			return null;
		}
		$curl_available = function_exists( 'curl_init' ) && ! ( defined( 'XMRPAY_TESTING_NO_CURL' ) && XMRPAY_TESTING_NO_CURL );
		if ( $curl_available ) {
			$ch = curl_init( $url );
			$raw = '';
			$oversized = false;
			curl_setopt_array( $ch, array(
				CURLOPT_WRITEFUNCTION => function ( $handle, $chunk ) use ( &$raw, &$oversized ) {
					if ( strlen( $raw ) + strlen( $chunk ) > 4 * 1024 * 1024 ) { $oversized = true; return 0; }
					$raw .= $chunk;
					return strlen( $chunk );
				},
				CURLOPT_TIMEOUT        => $this->http_timeout,
				CURLOPT_CONNECTTIMEOUT => $this->http_timeout,
				CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
				CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
				CURLOPT_FOLLOWLOCATION => false,
			) );
			if ( 'basic' === $node['auth'] ) {
				curl_setopt( $ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC );
				curl_setopt( $ch, CURLOPT_USERPWD, $node['username'] . ':' . $node['password'] );
			} elseif ( 'digest' === $node['auth'] ) {
				curl_setopt( $ch, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST );
				curl_setopt( $ch, CURLOPT_USERPWD, $node['username'] . ':' . $node['password'] );
			}
			if ( null !== $payload ) {
				curl_setopt( $ch, CURLOPT_POST, true );
				curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
				curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'Content-Type: application/json' ) );
			}
			$result = curl_exec( $ch );
			$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
			$errno = curl_errno( $ch );

			if ( false === $result ) {
				if ( $oversized ) { $this->set_node_error( 'response-too-large', $index, $node ); return null; }
				$this->set_node_error( 28 === $errno ? 'timeout' : 'node-unreachable', $index, $node );
				return null;
			}
			if ( $code < 200 || $code >= 300 ) {
				$this->set_node_error( $this->http_error_code( $code ), $index, $node );
				return null;
			}
			return $raw;
		}
		if ( 'digest' === $node['auth'] ) {
			$this->set_node_error( 'digest-unsupported', $index, $node );
			return null;
		}
		$headers = array();
		if ( 'basic' === $node['auth'] ) {
			$headers[] = 'Authorization: Basic ' . base64_encode( $node['username'] . ':' . $node['password'] );
		}
		$opts = array(
			'timeout'         => $this->http_timeout,
			'ignore_errors'   => true,
			'follow_location' => 0,
			'max_redirects'   => 0,
		);
		if ( null !== $payload ) {
			$opts['method']  = 'POST';
			$headers[]       = 'Content-Type: application/json';
			$opts['content'] = $payload;
		}
		if ( $headers ) {
			$opts['header'] = implode( "\r\n", $headers ) . "\r\n";
		}
		$ctx = stream_context_create( array( 'http' => $opts ) );
		$started = microtime( true );
		$stream = @fopen( $url, 'rb', false, $ctx );
		if ( false === $stream ) {
			$this->set_node_error( microtime( true ) - $started >= $this->http_timeout ? 'timeout' : 'node-unreachable', $index, $node );
			return null;
		}
		$raw = stream_get_contents( $stream, 4 * 1024 * 1024 + 1 );
		$meta = stream_get_meta_data( $stream );
		fclose( $stream );
		$status = $this->stream_status_code( isset( $meta['wrapper_data'] ) ? $meta['wrapper_data'] : array() );
		if ( ! empty( $meta['timed_out'] ) ) {
			$this->set_node_error( 'timeout', $index, $node );
			return null;
		}
		if ( $status < 200 || $status >= 300 ) {
			$code = 0 === $status ? 'node-unreachable' : $this->http_error_code( $status );
			$this->set_node_error( $code, $index, $node );
			return null;
		}
		return false === $raw ? null : $raw;
	}

	public function last_node_error() {
		return $this->last_node_error;
	}

	private function reset_node_error() {
		$this->last_node_error = array( 'code' => 'none', 'node_index' => null, 'url' => '' );
	}

	private function set_node_error( $code, $index, $node ) {
		$this->last_node_error = array(
			'code'       => (string) $code,
			'node_index' => (int) $index,
			'url'        => NodeConfig::publicUrl( isset( $node['url'] ) ? $node['url'] : '' ),
		);
	}

	private function decode_response( $raw, $index, $node ) {
		$decoded = json_decode( $raw, true );
		if ( ! is_array( $decoded ) ) {
			$this->set_node_error( 'malformed-response', $index, $node );
			return null;
		}
		return $decoded;
	}

	private function http_error_code( $status ) {
		if ( 401 === (int) $status || 403 === (int) $status ) { return 'authentication-rejected'; }
		if ( (int) $status >= 300 && (int) $status < 400 ) { return 'redirect-rejected'; }
		return 'http-error';
	}

	private function wp_error_code( $error ) {
		$code = method_exists( $error, 'get_error_code' ) ? strtolower( (string) $error->get_error_code() ) : '';
		return false !== strpos( $code, 'timeout' ) ? 'timeout' : 'node-unreachable';
	}

	private function stream_status_code( $headers ) {
		if ( ! isset( $headers[0] ) ) { return 0; }
		return preg_match( '#^HTTP/\S+\s+(\d{3})#i', $headers[0], $matches ) ? (int) $matches[1] : 0;
	}

	public function fetch_txs( $txids ) {
		$txids = array_values( array_filter( (array) $txids ) );
		if ( ! $txids ) { return array(); }
		$wanted = array();
		foreach ( $txids as $id ) {
			if ( ! is_string( $id ) || ! preg_match( '/^[0-9a-f]{64}$/i', $id ) ) { return null; }
			$wanted[ strtolower( $id ) ] = true;
		}
		if ( count( $wanted ) !== count( $txids ) ) { return null; }
		$body = array( 'txs_hashes' => $txids, 'decode_as_json' => true );
		$responses = array();
		if ( count( $this->nodes ) > 1 ) {

			foreach ( $this->nodes as $index => $node ) {
				$responses[] = $this->node_rpc_one( $node, $index, '/get_transactions', $body );
			}
		} else {
			$responses[] = $this->node_rpc( '/get_transactions', $body, 'txs' );
		}
		$baseline = null;
		$result = null;
		foreach ( $responses as $resp ) {
			if ( ! is_array( $resp ) || ! isset( $resp['txs'] ) || ! is_array( $resp['txs'] ) || count( $resp['txs'] ) !== count( $txids ) ) { return null; }
			$remaining = $wanted;
			$rows = array();
			$evidence = array();
			foreach ( $resp['txs'] as $tx ) {
				if ( ! is_array( $tx ) ) { return null; }
				$hash = strtolower( (string) ( $tx['tx_hash'] ?? '' ) );
				if ( ! isset( $remaining[ $hash ] ) ) { return null; }
				$asjson = isset( $tx['as_json'] ) ? json_decode( $tx['as_json'], true ) : null;
				if ( ! is_array( $asjson ) || ! isset( $asjson['extra'], $asjson['vout'] )
					|| ! is_array( $asjson['extra'] ) || ! is_array( $asjson['vout'] ) ) { return null; }
				unset( $remaining[ $hash ] );
				$asjson['_txid'] = $hash;
				$asjson['_block_height'] = isset( $tx['block_height'] ) ? (int) $tx['block_height'] : null;
				$asjson['_in_pool'] = ! empty( $tx['in_pool'] );
				$asjson['_double_spend_seen'] = ! empty( $tx['double_spend_seen'] );
				$rows[ $hash ] = $asjson;
				$evidence[ $hash ] = array(
					$asjson['_block_height'], $asjson['_in_pool'], $asjson['_double_spend_seen'],
					$asjson['unlock_time'] ?? 0,
					$asjson['extra'] ?? array(),
					$asjson['vout'] ?? array(),
					$asjson['rct_signatures']['ecdhInfo'] ?? array(),
					$asjson['rct_signatures']['outPk'] ?? ( $asjson['rctsig_prunable']['outPk'] ?? array() ),
				);
			}
			if ( null !== $baseline && $evidence != $baseline ) { return null; }
			$baseline = $evidence;
			$result = $rows;
		}
		return array_values( $result );
	}

	public function fetch_tx( $txid ) {
		$txs = $this->fetch_txs( array( $txid ) );
		if ( ! is_array( $txs ) || ! isset( $txs[0] ) ) { return null; }

		if ( strcasecmp( (string) $txs[0]['_txid'], (string) $txid ) !== 0 ) { return null; }
		return $txs[0];
	}

	public function verify_keys( $address, $view_key ) {
		try {
			$dec = $this->cn->decode_address( $address );
		} catch ( \Throwable $e ) {
			return array( 'address_valid' => false, 'key_match' => false );
		}
		if ( empty( $dec['viewKey'] ) || empty( $dec['spendKey'] ) ) {
			return array( 'address_valid' => false, 'key_match' => false );
		}
		$derived = '';
		try { $derived = $this->cn->pk_from_sk( trim( (string) $view_key ) ); } catch ( \Throwable $e ) { $derived = ''; }
		return array(
			'address_valid' => true,
			'key_match'     => '' !== $derived && hash_equals( strtolower( (string) $dec['viewKey'] ), strtolower( $derived ) ),
		);
	}

	public function address_valid( $address ) {
		try {
			$dec = $this->cn->decode_address( (string) $address );
		} catch ( \Throwable $e ) {
			return false;
		}
		if ( empty( $dec['viewKey'] ) || empty( $dec['spendKey'] ) ) {
			return false;
		}

		$valid = array(
			'mainnet'  => array( '12', '13', '2a' ),
			'stagenet' => array( '18', '19', '24' ),
			'testnet'  => array( '35', '36', '3f' ),
		);
		$allowed = isset( $valid[ $this->network ] ) ? $valid[ $this->network ] : $valid['mainnet'];
		$byte    = isset( $dec['networkByte'] ) ? strtolower( (string) $dec['networkByte'] ) : '';
		return in_array( $byte, $allowed, true );
	}

	public function node_info() {
		$this->reset_node_error();
		foreach ( $this->nodes as $index => $node ) {
			$r = $this->node_rpc_get_one( $node, $index, '/get_info' );
			if ( is_array( $r ) ) {
				$nettype = isset( $r['nettype'] ) ? (string) $r['nettype']
					: ( ! empty( $r['stagenet'] ) ? 'stagenet' : ( ! empty( $r['testnet'] ) ? 'testnet' : 'mainnet' ) );
				return array( 'ok' => true, 'height' => isset( $r['height'] ) ? (int) $r['height'] : null, 'nettype' => $nettype );
			}
		}
		$h = $this->tip_height();
		return null === $h ? array( 'ok' => false, 'height' => null, 'nettype' => 'unknown' )
			: array( 'ok' => true, 'height' => $h, 'nettype' => 'unknown' );
	}

	private function block_tx_hashes( $height ) {
		$body = array( 'jsonrpc' => '2.0', 'id' => '0', 'method' => 'get_block', 'params' => array( 'height' => (int) $height ) );
		$expected = null;
		foreach ( $this->nodes as $index => $node ) {
			$resp = $this->node_rpc_one( $node, $index, '/json_rpc', $body );
			$result = $resp['result'] ?? null;
			if ( ! is_array( $result ) ) { return null; }

			$block = isset( $result['json'] ) && is_string( $result['json'] ) ? json_decode( $result['json'], true ) : null;
			$list = $result['tx_hashes'] ?? ( $block['tx_hashes'] ?? null );
			if ( ! is_array( $list ) ) { return null; }
			$header = $result['block_header'] ?? array();
			if ( ! empty( $header['orphan_status'] )
				|| ( isset( $header['height'] ) && $header['height'] !== (int) $height )
				|| ( isset( $header['num_txes'] ) && $header['num_txes'] !== count( $list ) ) ) { return null; }
			$sorted = array();
			foreach ( $list as $hash ) {
				if ( ! is_string( $hash ) || ! preg_match( '/^[0-9a-f]{64}$/iD', $hash ) ) { return null; }
				$sorted[] = strtolower( $hash );
			}
			if ( count( array_unique( $sorted ) ) !== count( $sorted ) ) { return null; }
			sort( $sorted );
			$evidence = array( $header['hash'] ?? null, $sorted );
			if ( null !== $expected && $evidence !== $expected ) { return null; }
			$expected = $evidence;
		}
		return $sorted;
	}

	public function tip_height() {

		$heights = array();
		$this->reset_node_error();
		foreach ( $this->nodes as $index => $node ) {
			$r = $this->node_rpc_get_one( $node, $index, '/get_height' );
			if ( $r && isset( $r['height'] ) && (int) $r['height'] > 0 ) {
				$heights[] = (int) $r['height'];
			} elseif ( is_array( $r ) ) {
				$this->set_node_error( 'malformed-response', $index, $node );
			}
		}
		return $heights && count( $heights ) === count( $this->nodes ) ? min( $heights ) : null;
	}
	private function node_rpc_get_one( $node, $index, $path ) {
		$url = $node['url'] . $path;
		if ( 'none' === $node['auth'] && function_exists( 'wp_safe_remote_get' ) ) {
			$res = wp_safe_remote_get( $url, array(
				'timeout'             => $this->http_timeout,
				'redirection'         => 0,
				'limit_response_size' => 4 * 1024 * 1024,
			) );
			if ( is_wp_error( $res ) ) {
				$this->set_node_error( $this->wp_error_code( $res ), $index, $node );
				return null;
			}
			$code = (int) wp_remote_retrieve_response_code( $res );
			if ( $code < 200 || $code >= 300 ) {
				$this->set_node_error( $this->http_error_code( $code ), $index, $node );
				return null;
			}
			$raw = wp_remote_retrieve_body( $res );
			if ( strlen( $raw ) > 4 * 1024 * 1024 ) {
				$this->set_node_error( 'response-too-large', $index, $node );
				return null;
			}
			return $this->decode_response( $raw, $index, $node );
		}
		$raw = $this->http_raw( $url, null, $node, $index );
		if ( null === $raw ) { return null; }
		if ( strlen( $raw ) > 4 * 1024 * 1024 ) {
			$this->set_node_error( 'response-too-large', $index, $node );
			return null;
		}
		return $this->decode_response( $raw, $index, $node );
	}

	private function parse_extra( $extra_bytes ) {
		$n = count( $extra_bytes ); $pos = 0; $main = null; $additional = array();
		while ( $pos < $n ) {
			$tag = $extra_bytes[ $pos++ ];
			if ( 1 === $tag ) {
				$main = $this->take_hex( $extra_bytes, $pos, 32, $n );
				if ( null === $main ) { break; }
			} elseif ( 2 === $tag ) {
				$len = $this->read_varint( $extra_bytes, $pos, $n );
				$pos = min( $n, $pos + $len );
			} elseif ( 4 === $tag ) {
				$cnt = min( $this->read_varint( $extra_bytes, $pos, $n ), 256 );
				for ( $k = 0; $k < $cnt; $k++ ) {
					$h = $this->take_hex( $extra_bytes, $pos, 32, $n );
					if ( null === $h ) { break 2; }
					$additional[] = $h;
				}
			} elseif ( 0 === $tag ) {
				break;
			} else {
				break;
			}
		}
		return array( 'main' => $main, 'additional' => $additional );
	}
	private function read_varint( &$b, &$pos, $n ) {
		$r = 0; $shift = 0;
		while ( $pos < $n ) { $byte = $b[ $pos++ ]; $r |= ( $byte & 0x7f ) << $shift; if ( 0 === ( $byte & 0x80 ) ) { break; } $shift += 7; }
		return $r;
	}
	private function take_hex( &$b, &$pos, $len, $n = null ) {
		if ( null !== $n && $pos + $len > $n ) { $pos = $n; return null; }
		$h = '';
		for ( $k = 0; $k < $len; $k++ ) { $h .= str_pad( dechex( (int) $b[ $pos++ ] ), 2, '0', STR_PAD_LEFT ); }
		return $h;
	}

	private function le8_to_dec( $hex8 ) {
		$v = gmp_init( 0 ); $bs = str_split( $hex8, 2 );
		for ( $k = count( $bs ) - 1; $k >= 0; $k-- ) { $v = gmp_add( gmp_mul( $v, 256 ), gmp_init( hexdec( $bs[ $k ] ), 10 ) ); }
		return gmp_strval( $v );
	}

	private function decode_amount( $derivation, $i, $ecdh_hex ) {
		$sk     = $this->cn->derivation_to_scalar( $derivation, $i );
		$factor = $this->cn->keccak_256( bin2hex( 'amount' ) . $sk );
		$mask8  = substr( $factor, 0, 16 );
		$amt    = strlen( $ecdh_hex ) >= 16 ? substr( $ecdh_hex, 0, 16 ) : str_pad( $ecdh_hex, 16, '0' );
		return $this->le8_to_dec( bin2hex( hex2bin( $amt ) ^ hex2bin( $mask8 ) ) );
	}

	public function check_commitment( $amount_atomic, $derivation, $i, $commitment_hex ) {
		if ( '' === (string) $commitment_hex || null === $commitment_hex ) {
			return false;
		}
		$ed   = $this->cn_ed();
		$sk   = $this->cn->derivation_to_scalar( $derivation, $i );
		$mask = $this->cn->hash_to_scalar( bin2hex( 'commitment_mask' ) . $sk );

		$H    = $ed->decodepoint( hex2bin( self::H_POINT ) );
		$aH   = ( '0' === (string) $amount_atomic ) ? array( 0, 1 ) : $ed->scalarmult( $H, gmp_init( $amount_atomic, 10 ) );

		$mG   = $ed->scalarmult_base( $ed->decodeint( hex2bin( $mask ) ) );
		$C    = bin2hex( $ed->encodepoint( $ed->edwards( $aH, $mG ) ) );
		return hash_equals( strtolower( (string) $commitment_hex ), strtolower( $C ) );
	}
	private function cn_ed() {

		$ref = new \ReflectionProperty( get_class( $this->cn ), 'ed25519' );
		if ( \PHP_VERSION_ID < 80100 ) { $ref->setAccessible( true ); }
		return $ref->getValue( $this->cn );
	}

	public function verify_payment( $txid, $address, $view_key, $opts = array() ) {
		$require_commitment = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$tip                = isset( $opts['tip'] ) ? (int) $opts['tip'] : null;
		$tx = $this->fetch_tx( $txid );
		if ( ! $tx ) {
			return array( 'found' => false, 'reason' => 'node did not return the tx' );
		}
		return $this->classify_tx( $tx, $address, $view_key, $tip, $require_commitment );
	}

	public function detect_in_tx( $tx, $address, $view_key ) {
		$dec = $this->cn->decode_address( $address );
		if ( empty( $dec['spendKey'] ) ) { return null; }
		$C_spend = $dec['spendKey'];
		$extra = $this->parse_extra( isset( $tx['extra'] ) ? $tx['extra'] : array() );
		$vout  = isset( $tx['vout'] ) ? $tx['vout'] : array();
		if ( count( $vout ) > 256 ) { return null; }
		$ecdh  = isset( $tx['rct_signatures']['ecdhInfo'] ) ? $tx['rct_signatures']['ecdhInfo'] : array();
		$outpk = isset( $tx['rct_signatures']['outPk'] ) ? $tx['rct_signatures']['outPk'] : ( isset( $tx['rctsig_prunable']['outPk'] ) ? $tx['rctsig_prunable']['outPk'] : array() );
		for ( $i = 0; $i < count( $vout ); $i++ ) {
			$t       = ( isset( $vout[ $i ]['target'] ) && is_array( $vout[ $i ]['target'] ) ) ? $vout[ $i ]['target'] : array();
			$out_key = isset( $t['key'] ) ? $t['key'] : ( isset( $t['tagged_key']['key'] ) ? $t['tagged_key']['key'] : null );
			if ( ! $out_key ) { continue; }
			$candidates = array();
			if ( isset( $extra['additional'][ $i ] ) ) { $candidates[] = $extra['additional'][ $i ]; }
			if ( $extra['main'] ) { $candidates[] = $extra['main']; }
			foreach ( $candidates as $R ) {

				try {
					$derivation = $this->cn->gen_key_derivation( $R, $view_key );
					$owned      = ( $this->cn->derive_public_key( $derivation, $i, $C_spend ) === $out_key );
				} catch ( \Throwable $e ) {
					continue;
				}
				if ( ! $owned ) { continue; }

				try {
					$amt_hex       = isset( $ecdh[ $i ]['amount'] ) ? $ecdh[ $i ]['amount'] : '';
					$amount_atomic = '' !== $amt_hex ? $this->decode_amount( $derivation, $i, $amt_hex ) : '0';
					$commitment    = $this->outpk_mask( $outpk, $i );
					return array(
						'output_index'  => $i,
						'amount_atomic' => $amount_atomic,
						'out_key'       => $out_key,

						'commitment_present' => ( '' !== (string) $commitment && null !== $commitment ),
						'commitment_ok' => $commitment ? $this->check_commitment( $amount_atomic, $derivation, $i, $commitment ) : false,
					);
				} catch ( \Throwable $e ) {

					return array(
						'output_index'      => $i,
						'amount_atomic'     => '0',
						'out_key'           => $out_key,
						'commitment_present' => false,
						'commitment_ok'     => false,
						'errored'           => true,
					);
				}
			}
		}
		return null;
	}

	private function classify_tx( $tx, $address, $view_key, $tip, $require_commitment ) {
		$m = $this->detect_in_tx( $tx, $address, $view_key );
		if ( null === $m ) { return array( 'found' => false, 'reason' => 'no output to this address' ); }
		if ( $require_commitment && empty( $m['commitment_ok'] ) ) {
			$present = ! empty( $m['commitment_present'] );
			return array( 'found' => true, 'amount_atomic' => $m['amount_atomic'], 'output_index' => $m['output_index'], 'out_key' => isset( $m['out_key'] ) ? $m['out_key'] : '', 'commitment_ok' => false, 'commitment_present' => $present,
				'reason' => $present ? 'commitment mismatch: decoded amount not committed on-chain' : 'commitment unavailable: the node may be pruned; use a full (non-pruned) node' );
		}
		$bh   = isset( $tx['_block_height'] ) ? $tx['_block_height'] : null;
		$conf = ( null !== $bh && null !== $tip && $bh > 0 ) ? max( 0, $tip - $bh ) : ( ! empty( $tx['_in_pool'] ) ? 0 : null );
		return array(
			'found'         => true,
			'amount_atomic' => $m['amount_atomic'],
			'output_index'  => $m['output_index'],
			'confirmations' => $conf,
			'in_pool'       => ! empty( $tx['_in_pool'] ),
			'double_spend_seen' => ! empty( $tx['_double_spend_seen'] ),
			'locked'        => $this->is_locked( isset( $tx['unlock_time'] ) ? $tx['unlock_time'] : 0, $bh, $conf, $tip ),
			'out_key'       => isset( $m['out_key'] ) ? $m['out_key'] : '',
						'commitment_ok' => $m['commitment_ok'],
			'reason'        => 'ok',
		);
	}

	public function subaddress( $major, $minor, $view_key, $primary_address ) {
		$dec = $this->cn->decode_address( $primary_address );
		if ( empty( $dec['spendKey'] ) ) { return null; }
		if ( 0 === (int) $major && 0 === (int) $minor ) {
			return array( 'address' => $primary_address, 'spend_pub' => $dec['spendKey'] );
		}
		$addr = $this->cn->generate_subaddress( (int) $major, (int) $minor, $view_key, $dec['spendKey'] );
		$sdec = $this->cn->decode_address( $addr );
		return array( 'address' => $addr, 'spend_pub' => isset( $sdec['spendKey'] ) ? $sdec['spendKey'] : '' );
	}

	public function scan( $address, $view_key, $from_height, $to_height, $opts = array() ) {
		$max_blocks = isset( $opts['max_blocks'] ) ? max( 1, (int) $opts['max_blocks'] ) : 30;
		$budget_s   = isset( $opts['time_budget'] ) ? (float) $opts['time_budget'] : 8.0;
		$req_commit = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$tip        = isset( $opts['tip'] ) ? (int) $opts['tip'] : (int) $to_height;
		$start      = microtime( true );
		$h          = (int) $from_height;
		$end        = min( (int) $to_height, $h + $max_blocks - 1 );
		$last       = $h - 1;
		for ( ; $h <= $end; $h++ ) {
			if ( ( microtime( true ) - $start ) > $budget_s ) { break; }
			$hashes = $this->block_tx_hashes( $h );
			if ( null === $hashes ) { break; }
			$incomplete = false;
			foreach ( array_chunk( $hashes, 50 ) as $batch ) {
				$txs = $this->fetch_txs( $batch );
				if ( null === $txs ) { $incomplete = true; continue; }
				foreach ( $txs as $tx ) {
					if ( ! empty( $tx['_in_pool'] ) || ! isset( $tx['_block_height'] ) || (int) $tx['_block_height'] !== $h ) {
						$incomplete = true;
						continue;
					}
					$m = $this->detect_in_tx( $tx, $address, $view_key );
					if ( null === $m ) { continue; }
					if ( $req_commit && empty( $m['commitment_ok'] ) ) { continue; }
					$bh   = isset( $tx['_block_height'] ) ? (int) $tx['_block_height'] : $h;
					$conf = max( 0, $tip - $bh );
					return array(
						'found'         => true,
						'txid'          => isset( $tx['_txid'] ) ? $tx['_txid'] : '',
						'amount_atomic' => $m['amount_atomic'],
						'output_index'  => $m['output_index'],
						'confirmations' => $conf,
						'in_pool'       => false,
						'locked'        => $this->is_locked( isset( $tx['unlock_time'] ) ? $tx['unlock_time'] : 0, $bh, $conf, $tip ),
						'out_key'       => isset( $m['out_key'] ) ? $m['out_key'] : '',
						'commitment_ok' => $m['commitment_ok'],
						'block_height'  => $bh,
					);
				}
			}
			if ( $incomplete ) { return array( 'found' => false, 'scanned_to' => $last ); }
			$last = $h;
		}
		return array( 'found' => false, 'scanned_to' => $last );
	}

	public function scan_all( $address, $view_key, $from_height, $to_height, $opts = array() ) {
		$max_blocks = isset( $opts['max_blocks'] ) ? max( 1, (int) $opts['max_blocks'] ) : 30;
		$budget_s   = isset( $opts['time_budget'] ) ? (float) $opts['time_budget'] : 8.0;
		$req_commit = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$tip        = isset( $opts['tip'] ) ? (int) $opts['tip'] : (int) $to_height;
		$start      = microtime( true );
		$h          = (int) $from_height;
		$end        = min( (int) $to_height, $h + $max_blocks - 1 );
		$last       = $h - 1;
		$matches    = array();
		for ( ; $h <= $end; $h++ ) {
			if ( ( microtime( true ) - $start ) > $budget_s ) { break; }
			$hashes = $this->block_tx_hashes( $h );
			if ( null === $hashes ) { break; }
			$incomplete = false;
			foreach ( array_chunk( $hashes, 50 ) as $batch ) {
				$txs = $this->fetch_txs( $batch );
				if ( null === $txs ) { $incomplete = true; continue; }
				foreach ( $txs as $tx ) {
					if ( ! empty( $tx['_in_pool'] ) || ! isset( $tx['_block_height'] ) || (int) $tx['_block_height'] !== $h ) {
						$incomplete = true;
						continue;
					}
					$m = $this->detect_in_tx( $tx, $address, $view_key );
					if ( null === $m ) { continue; }
					if ( $req_commit && empty( $m['commitment_ok'] ) ) { continue; }
					$bh   = isset( $tx['_block_height'] ) ? (int) $tx['_block_height'] : $h;
					$conf = max( 0, $tip - $bh );
					$matches[] = array(
						'txid'          => isset( $tx['_txid'] ) ? $tx['_txid'] : '',
						'amount_atomic' => $m['amount_atomic'],
						'output_index'  => $m['output_index'],
						'confirmations' => $conf,
						'in_pool'       => false,
						'locked'        => $this->is_locked( isset( $tx['unlock_time'] ) ? $tx['unlock_time'] : 0, $bh, $conf, $tip ),
						'out_key'       => isset( $m['out_key'] ) ? $m['out_key'] : '',
						'commitment_ok' => $m['commitment_ok'],
						'block_height'  => $bh,
					);
				}
			}
			if ( $incomplete ) { return array( 'matches' => $matches, 'scanned_to' => $last ); }
			$last = $h;
		}
		return array( 'matches' => $matches, 'scanned_to' => $last );
	}

	private function outpk_mask( $outpk, $i ) {
		if ( ! isset( $outpk[ $i ] ) ) { return null; }
		$v = $outpk[ $i ];
		if ( is_string( $v ) ) { return $v; }
		if ( is_array( $v ) && isset( $v['mask'] ) ) { return $v['mask']; }
		return null;
	}

	private function is_locked( $unlock_time, $block_height, $conf, $tip ) {
		$ut = (int) $unlock_time;
		if ( 0 === $ut ) { return false; }
		if ( $ut < 500000000 ) {
			if ( null === $tip ) { return true; }
			return $ut > ( $tip - 1 );
		}
		return $ut > ( time() - 1 );
	}
}
