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
	private $curl_handles = array();
	private $unsupported_outputs = 0;
	private $deadline = null;
	private $last_block_hash = null;
	private $last_previous_hash = null;
	private $last_node_error = array( 'code' => 'none', 'node_index' => null, 'url' => '' );

	public function __construct( $node, $network = 'mainnet', $http_timeout = 20, $minimum_nodes = 1 ) {

		$this->nodes        = NodeConfig::normalizeList( $node );
		if ( ! is_int( $minimum_nodes ) || $minimum_nodes < 1 ) {
			throw new \InvalidArgumentException( 'invalid-minimum-node-count' );
		}
		$authorities = array();
		foreach ( $this->nodes as $configuredNode ) {
			$parts = parse_url( $configuredNode['url'] );
			$host = strtolower( rtrim( $parts['host'], '.' ) );
			$defaultPort = strtolower( $parts['scheme'] ) === 'https' ? 443 : 80;
			$port = $parts['port'] ?? $defaultPort;
			$authorities[ $host . ':' . $port ] = true;
		}
		if ( count( $authorities ) < $minimum_nodes ) {
			throw new \InvalidArgumentException( 'insufficient-distinct-nodes' );
		}
		$this->http_timeout = (int) $http_timeout;
		$this->network      = in_array( $network, array( 'mainnet', 'stagenet', 'testnet' ), true ) ? $network : 'mainnet';
		$this->cn           = new Cryptonote( $this->network );
	}

	/** Apply one budget across tip lookup, acquisition, detection and canonical validation. */
	public function set_time_budget( $seconds ) {
		$seconds = (float) $seconds;
		if ( ! is_finite( $seconds ) || $seconds < 0 ) { throw new \InvalidArgumentException( 'invalid-time-budget' ); }
		$this->deadline = hrtime( true ) / 1000000000 + $seconds;
	}

	public function budget_exhausted() {
		return $this->deadline !== null && hrtime( true ) / 1000000000 >= $this->deadline;
	}

	public function remaining_time() {
		$remaining = (float) $this->http_timeout;
		if ( $this->deadline !== null ) { $remaining = min( $remaining, $this->deadline - hrtime( true ) / 1000000000 ); }
		return max( 0.0, $remaining );
	}

	private function acquire_rpc( $node, $index, $path, $body ) {
		if ( $this->remaining_time() <= 0 ) { return null; }
		$response = $this->node_rpc_one( $node, $index, $path, $body );
		return $this->budget_exhausted() ? null : $response;
	}

	private function acquire_rpc_get( $node, $index, $path ) {
		if ( $this->remaining_time() <= 0 ) { return null; }
		$response = $this->node_rpc_get_one( $node, $index, $path );
		return $this->budget_exhausted() ? null : $response;
	}

	private function node_rpc( $path, $body, $required_array_key = null ) {

		$this->reset_node_error();
		foreach ( $this->nodes as $index => $node ) {
			$r = $this->acquire_rpc( $node, $index, $path, $body );
			if ( null === $r ) { continue; }
			if ( null === $required_array_key || ( isset( $r[ $required_array_key ] ) && is_array( $r[ $required_array_key ] ) ) ) {
				return $r;
			}
			$this->set_node_error( 'malformed-response', $index, $node );
		}
		return null;
	}

	protected function node_rpc_one( $node, $index, $path, $body ) {
		$url     = $node['url'] . $path;
		$payload = function_exists( 'wp_json_encode' ) ? wp_json_encode( $body ) : json_encode( $body );
		if ( 'none' === $node['auth'] && function_exists( 'wp_safe_remote_post' ) ) {
			$res = $this->wordpress_request( $url, array(
				'timeout'             => $this->remaining_time(),
				'redirection'         => 0,
				'headers'             => array( 'Content-Type' => 'application/json' ),
				'body'                => $payload,
				'limit_response_size' => 4 * 1024 * 1024,
			), 'wp_safe_remote_post' );
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

	private function wordpress_request( $url, $args, $function ) {
		$hook = null;
		if ( $this->deadline !== null && function_exists( 'add_action' ) && function_exists( 'curl_setopt' ) ) {
			$hook = function ( $handle, $request_args, $request_url ) use ( $url ) {
				if ( $request_url !== $url ) { return; }
				$milliseconds = max( 1, (int) ceil( $this->remaining_time() * 1000 ) );
				foreach ( array( CURLOPT_TIMEOUT_MS => $milliseconds, CURLOPT_CONNECTTIMEOUT_MS => $milliseconds, CURLOPT_NOSIGNAL => true ) as $option => $value ) {
					if ( is_object( $handle ) && method_exists( $handle, 'setopt' ) ) { $handle->setopt( $option, $value ); }
					else { curl_setopt( $handle, $option, $value ); }
				}
			};
			add_action( 'http_api_curl', $hook, 10, 3 );
		}
		try {
			return $function( $url, $args );
		} finally {
			if ( $hook ) { remove_action( 'http_api_curl', $hook, 10 ); }
		}
	}

	private function http_raw( $url, $payload, $node, $index ) {
		if ( ! in_array( strtolower( (string) parse_url( $url, PHP_URL_SCHEME ) ), array( 'http', 'https' ), true ) ) {
			$this->set_node_error( 'invalid-scheme', $index, $node );
			return null;
		}
		$timeout = $this->remaining_time();
		if ( $timeout <= 0 ) { return null; }
		$timeout_ms = max( 1, (int) ceil( $timeout * 1000 ) );
		$curl_available = function_exists( 'curl_init' ) && ! ( defined( 'XMRPAY_TESTING_NO_CURL' ) && XMRPAY_TESTING_NO_CURL );
		if ( $curl_available ) {
			if ( ! isset( $this->curl_handles[$index] ) ) {
				$this->curl_handles[$index] = curl_init();
			}
			$ch = $this->curl_handles[$index];
			curl_reset( $ch );
			$raw = '';
			$oversized = false;
			curl_setopt_array( $ch, array(
				CURLOPT_URL => $url,
				CURLOPT_WRITEFUNCTION => static function ( $handle, $chunk ) use ( &$raw, &$oversized ) {
					if ( strlen( $raw ) + strlen( $chunk ) > 4 * 1024 * 1024 ) { $oversized = true; return 0; }
					$raw .= $chunk;
					return strlen( $chunk );
				},
				CURLOPT_TIMEOUT_MS     => $timeout_ms,
				CURLOPT_CONNECTTIMEOUT_MS => $timeout_ms,
				CURLOPT_NOSIGNAL       => true,
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
			'timeout'         => $timeout,
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
			$this->set_node_error( microtime( true ) - $started >= $timeout ? 'timeout' : 'node-unreachable', $index, $node );
			return null;
		}
		stream_set_blocking( $stream, false );
		$raw = '';
		while ( ! feof( $stream ) && strlen( $raw ) <= 4 * 1024 * 1024 ) {
			$remaining = $this->remaining_time();
			if ( $remaining <= 0 ) { fclose( $stream ); return null; }
			$seconds = (int) floor( $remaining );
			$microseconds = max( 1, (int) floor( ( $remaining - $seconds ) * 1000000 ) );
			$readable = array( $stream );
			$writable = null;
			$exceptional = null;
			$ready = @stream_select( $readable, $writable, $exceptional, $seconds, $microseconds );
			if ( $ready === false ) { fclose( $stream ); return null; }
			if ( $ready === 0 ) { break; }
			$chunk = fread( $stream, 8192 );
			if ( $chunk === false ) { fclose( $stream ); return null; }
			$raw .= $chunk;
			$metadata = stream_get_meta_data( $stream );
			if ( ! empty( $metadata['timed_out'] ) ) { break; }
		}
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

	protected function set_node_error( $code, $index, $node ) {
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
		// FCMP++ JSON proofs make fifty decoded transactions exceed the per-reply cap.
		if ( count( $txids ) > 10 ) {
			$transactions = array();
			foreach ( array_chunk( $txids, 10 ) as $batch ) {
				$rows = $this->fetch_txs( $batch );
				if ( $rows === null ) { return null; }
				foreach ( $rows as $row ) { $transactions[] = $row; }
			}
			return $transactions;
		}
		$body = array( 'txs_hashes' => $txids, 'decode_as_json' => true );
		$responses = array();
		if ( count( $this->nodes ) > 1 ) {

			foreach ( $this->nodes as $index => $node ) {
				$responses[] = $this->acquire_rpc( $node, $index, '/get_transactions', $body );
			}
		} else {
			$responses[] = $this->node_rpc( '/get_transactions', $body, 'txs' );
		}
		$baseline = null;
		$result = null;
		foreach ( $responses as $index => $resp ) {
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
					$asjson['version'] ?? null, $asjson['vin'] ?? array(),
					$asjson['rct_signatures']['type'] ?? null,
					$asjson['extra'] ?? array(),
					$asjson['vout'] ?? array(),
					$asjson['rct_signatures']['ecdhInfo'] ?? array(),
					$asjson['rct_signatures']['outPk'] ?? ( $asjson['rctsig_prunable']['outPk'] ?? array() ),
				);
			}
			if ( null !== $baseline && $evidence != $baseline ) {
				$this->set_node_error( 'node-disagreement', $index, $this->nodes[$index] );
				return null;
			}
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
			$r = $this->acquire_rpc_get( $node, $index, '/get_info' );
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

	/** Operational declarations only; receipt and canonical-chain checks remain separate. */
	public function node_health(): array {
		$nodes = array();
		$ready = true;
		$firstHead = null;
		$disagrees = false;
		foreach ( $this->nodes as $index => $node ) {
			$this->reset_node_error();
			$info = $this->acquire_rpc_get( $node, $index, '/get_info' );
			$status = 'unavailable';
			if ( is_array( $info ) ) {
				$status = $this->node_health_status( $info );
			} elseif ( $this->budget_exhausted() ) {
				$status = 'budget-exhausted';
			}
			$snapshot = array( 'node_index' => $index, 'status' => $status, 'height' => null,
				'target_height' => null, 'nettype' => null, 'top_block_hash' => null,
				'synchronized' => null, 'busy_syncing' => null, 'offline' => null,
				'node_error' => $this->last_node_error['code'] );
			if ( is_array( $info ) ) {
				foreach ( array( 'height', 'target_height' ) as $field ) {
					if ( isset( $info[ $field ] ) && is_int( $info[ $field ] ) && $info[ $field ] >= 0 ) {
						$snapshot[ $field ] = $info[ $field ];
					}
				}
				foreach ( array( 'synchronized', 'busy_syncing', 'offline' ) as $field ) {
					if ( isset( $info[ $field ] ) && is_bool( $info[ $field ] ) ) {
						$snapshot[ $field ] = $info[ $field ];
					}
				}
				if ( isset( $info['nettype'] ) && in_array( $info['nettype'], array( 'mainnet', 'testnet', 'stagenet', 'fakechain' ), true ) ) {
					$snapshot['nettype'] = $info['nettype'];
				}
				if ( isset( $info['top_block_hash'] ) && is_string( $info['top_block_hash'] )
					&& preg_match( '/^[0-9a-f]{64}$/iD', $info['top_block_hash'] ) ) {
					$snapshot['top_block_hash'] = strtolower( $info['top_block_hash'] );
				}
			}
			$nodes[] = $snapshot;
			if ( $status !== 'ready' ) {
				$ready = false;
				continue;
			}
			$head = array( $snapshot['height'], $snapshot['top_block_hash'] );
			if ( $firstHead !== null && $firstHead !== $head ) { $disagrees = true; }
			$firstHead = $head;
		}
		$ready = $ready && ! $disagrees && count( $nodes ) > 0;
		$status = 'degraded';
		if ( $disagrees ) { $status = 'node-disagreement'; }
		elseif ( $ready ) { $status = 'ready'; }
		return array( 'ready' => $ready, 'status' => $status,
			'observed_at' => time(), 'nodes' => $nodes );
	}

	private function node_health_status( array $info ): string {
		if ( ( $info['status'] ?? null ) !== 'OK' ) { return 'unavailable'; }
		foreach ( array( 'height', 'target_height', 'nettype', 'top_block_hash', 'synchronized', 'busy_syncing', 'offline' ) as $field ) {
			if ( ! array_key_exists( $field, $info ) ) { return 'unknown'; }
		}
		if ( ! is_int( $info['height'] ) || $info['height'] <= 0
			|| ! is_int( $info['target_height'] ) || $info['target_height'] < 0
			|| ! is_string( $info['nettype'] ) || ! is_string( $info['top_block_hash'] )
			|| ! preg_match( '/^[0-9a-f]{64}$/iD', $info['top_block_hash'] ) ) { return 'invalid-response'; }
		foreach ( array( 'synchronized', 'busy_syncing', 'offline' ) as $field ) {
			if ( ! is_bool( $info[ $field ] ) ) { return 'invalid-response'; }
		}
		if ( $info['nettype'] !== $this->network ) { return 'wrong-network'; }
		if ( $info['offline'] ) { return 'offline'; }
		if ( ! $info['synchronized'] || $info['busy_syncing'] || $info['target_height'] > $info['height'] ) { return 'syncing'; }
		return 'ready';
	}

	private function block_tx_hashes( $height ) {
		$this->last_block_hash = null;
		$this->last_previous_hash = null;
		$body = array( 'jsonrpc' => '2.0', 'id' => '0', 'method' => 'get_block', 'params' => array( 'height' => (int) $height ) );
		$expected = null;
		foreach ( $this->nodes as $index => $node ) {
			$resp = $this->acquire_rpc( $node, $index, '/json_rpc', $body );
			$result = $resp['result'] ?? null;
			if ( ! is_array( $result ) ) { return null; }

			$block = isset( $result['json'] ) && is_string( $result['json'] ) ? json_decode( $result['json'], true ) : null;
			$list = $result['tx_hashes'] ?? ( $block['tx_hashes'] ?? null );
			if ( ! is_array( $list ) ) { return null; }
			$header = $result['block_header'] ?? array();
			if ( ! is_array( $header ) || ! isset( $header['hash'], $header['prev_hash'], $header['height'] ) ) {
				return null;
			}
			if ( ! is_int( $header['height'] ) || $header['height'] !== (int) $height ) {
				return null;
			}
			foreach ( array( 'hash', 'prev_hash' ) as $field ) {
				if ( ! is_string( $header[ $field ] ) || ! preg_match( '/^[0-9a-f]{64}$/iD', $header[ $field ] ) ) {
					return null;
				}
			}
			if ( ! empty( $header['orphan_status'] )
				|| ( isset( $header['num_txes'] ) && $header['num_txes'] !== count( $list ) ) ) { return null; }
			$sorted = array();
			foreach ( $list as $hash ) {
				if ( ! is_string( $hash ) || ! preg_match( '/^[0-9a-f]{64}$/iD', $hash ) ) { return null; }
				$sorted[] = strtolower( $hash );
			}
			if ( count( array_unique( $sorted ) ) !== count( $sorted ) ) { return null; }
			sort( $sorted );
			$evidence = array( $header['hash'] ?? null, $sorted, $header['prev_hash'] ?? null );
			if ( null !== $expected && $evidence !== $expected ) {
				$this->set_node_error( 'node-disagreement', $index, $node );
				return null;
			}
			$expected = $evidence;
		}
		$this->last_block_hash = isset( $expected[0] ) ? strtolower( $expected[0] ) : null;
		$this->last_previous_hash = isset( $expected[2] ) ? strtolower( $expected[2] ) : null;
		return $sorted;
	}

	public function tip_height() {

		$heights = array();
		$this->reset_node_error();
		foreach ( $this->nodes as $index => $node ) {
			$r = $this->acquire_rpc_get( $node, $index, '/get_height' );
			if ( $r && isset( $r['height'] ) && (int) $r['height'] > 0 ) {
				$heights[] = (int) $r['height'];
			} elseif ( is_array( $r ) ) {
				$this->set_node_error( 'malformed-response', $index, $node );
			}
		}
		return $heights && count( $heights ) === count( $this->nodes ) ? min( $heights ) : null;
	}
	protected function node_rpc_get_one( $node, $index, $path ) {
		$url = $node['url'] . $path;
		if ( 'none' === $node['auth'] && function_exists( 'wp_safe_remote_get' ) ) {
			$res = $this->wordpress_request( $url, array(
				'timeout'             => $this->remaining_time(),
				'redirection'         => 0,
				'limit_response_size' => 4 * 1024 * 1024,
			), 'wp_safe_remote_get' );
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

	private function decode_legacy_amount( $derivation, $i, $ecdh ) {
		if ( ! is_array( $ecdh ) || ! is_string( $ecdh['mask'] ?? null ) || ! is_string( $ecdh['amount'] ?? null )
			|| ! preg_match( '/^[0-9a-f]{64}$/iD', $ecdh['mask'] ) || ! preg_match( '/^[0-9a-f]{64}$/iD', $ecdh['amount'] ) ) {
			throw new \UnexpectedValueException( 'Invalid legacy RingCT encoding' );
		}
		$ed = $this->cn_ed();
		$encoded_mask = $ed->decodeint( hex2bin( $ecdh['mask'] ) );
		$encoded_amount = $ed->decodeint( hex2bin( $ecdh['amount'] ) );
		if ( gmp_cmp( $encoded_mask, $ed->l ) >= 0 || gmp_cmp( $encoded_amount, $ed->l ) >= 0 ) {
			throw new \UnexpectedValueException( 'Noncanonical legacy RingCT scalar' );
		}
		// Monero rctOps.cpp ecdhDecode uses two hashed scalars for RingCT types 1-3.
		$shared_secret = $this->cn->derivation_to_scalar( $derivation, $i );
		$mask_hash = $this->cn->hash_to_scalar( $shared_secret );
		$amount_hash = $this->cn->hash_to_scalar( $mask_hash );
		$mask = gmp_mod( gmp_sub( $encoded_mask, $ed->decodeint( hex2bin( $mask_hash ) ) ), $ed->l );
		$amount = gmp_mod( gmp_sub( $encoded_amount, $ed->decodeint( hex2bin( $amount_hash ) ) ), $ed->l );
		if ( gmp_cmp( $amount, '18446744073709551615' ) > 0 ) {
			throw new \UnexpectedValueException( 'Legacy RingCT amount exceeds uint64' );
		}
		return array( 'amount_atomic' => gmp_strval( $amount ), 'mask' => $mask );
	}

	public function check_commitment( $amount_atomic, $derivation, $i, $commitment_hex ) {
		if ( '' === (string) $commitment_hex || null === $commitment_hex ) {
			return false;
		}
		$ed   = $this->cn_ed();
		$sk   = $this->cn->derivation_to_scalar( $derivation, $i );
		$mask = $this->cn->hash_to_scalar( bin2hex( 'commitment_mask' ) . $sk );
		return $this->check_commitment_with_mask( $amount_atomic, $ed->decodeint( hex2bin( $mask ) ), $commitment_hex );
	}

	private function check_commitment_with_mask( $amount_atomic, $mask, $commitment_hex ) {
		$ed   = $this->cn_ed();
		$H    = $ed->decodepoint( hex2bin( self::H_POINT ) );
		$aH   = ( '0' === (string) $amount_atomic ) ? array( 0, 1 ) : $ed->scalarmult( $H, gmp_init( $amount_atomic, 10 ) );

		$mG   = $ed->scalarmult_base( $mask );
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
			return array( 'found' => false, 'budget_exhausted' => $this->budget_exhausted(), 'reason' => $this->budget_exhausted() ? 'time budget exhausted' : 'node did not return the tx' );
		}
		return $this->classify_tx( $tx, $address, $view_key, $tip, $require_commitment );
	}

	/** Return independently classified outputs for callers that account for a whole transaction. */
	public function verify_payments( $txid, $address, $view_key, $opts = array() ) {
		$tx = $this->fetch_tx( $txid );
		if ( ! $tx ) { return array( 'matches' => array(), 'unsupported_outputs' => 0, 'budget_exhausted' => $this->budget_exhausted(), 'reason' => $this->budget_exhausted() ? 'time budget exhausted' : 'node did not return the tx' ); }
		return $this->classify_payments( $tx, $address, $view_key, $opts );
	}

	/** Classify an already acquired transaction without performing network requests. */
	public function classify_payments( $tx, $address, $view_key, $opts = array() ) {
		$tip = isset( $opts['tip'] ) ? (int) $opts['tip'] : null;
		$require = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$matches = array();
		foreach ( $this->detect_all_in_tx( $tx, $address, $view_key ) as $match ) {
			$matches[] = $this->classify_match( $match, $tx, $tip, $require );
		}
		if ( $this->budget_exhausted() ) { return array( 'matches' => array(), 'unsupported_outputs' => 0, 'budget_exhausted' => true, 'reason' => 'time budget exhausted' ); }
		return array( 'matches' => $matches, 'unsupported_outputs' => $this->unsupported_outputs, 'budget_exhausted' => false );
	}

	/** First-match compatibility API; use detect_all_in_tx for payment accounting. */
	public function detect_in_tx( $tx, $address, $view_key ) {
		$matches = $this->detect_all_in_tx( $tx, $address, $view_key );
		return $matches ? $matches[0] : null;
	}

	/** Recognize every classic output without losing its individual identity. */
	public function detect_all_in_tx( $tx, $address, $view_key ) {
		$this->unsupported_outputs = 0;
		if ( $this->budget_exhausted() ) { return array(); }
		$dec = $this->cn->decode_address( $address );
		if ( empty( $dec['spendKey'] ) ) { return array(); }
		$C_spend = $dec['spendKey'];
		$extra = $this->parse_extra( isset( $tx['extra'] ) && is_array( $tx['extra'] ) ? $tx['extra'] : array() );
		$vout = isset( $tx['vout'] ) && is_array( $tx['vout'] ) ? $tx['vout'] : array();
		if ( count( $vout ) > 256 ) { $this->unsupported_outputs = count( $vout ); return array(); }
		$ecdh = $tx['rct_signatures']['ecdhInfo'] ?? array();
		$outpk = $tx['rct_signatures']['outPk'] ?? ( $tx['rctsig_prunable']['outPk'] ?? array() );
		$matches = array();
		for ( $i = 0; $i < count( $vout ); $i++ ) {
			if ( $this->budget_exhausted() ) { return array(); }
			$t       = ( isset( $vout[ $i ]['target'] ) && is_array( $vout[ $i ]['target'] ) ) ? $vout[ $i ]['target'] : array();
			$out_key = isset( $t['key'] ) ? $t['key'] : ( isset( $t['tagged_key']['key'] ) ? $t['tagged_key']['key'] : null );
			if ( ! is_string( $out_key ) || count( $t ) !== 1 ) { $this->unsupported_outputs++; continue; }
			$candidates = array();
			if ( isset( $extra['additional'][ $i ] ) ) { $candidates[] = $extra['additional'][ $i ]; }
			if ( $extra['main'] ) { $candidates[] = $extra['main']; }
			foreach ( $candidates as $R ) {
				if ( $this->budget_exhausted() ) { return array(); }

				try {
					$derivation = $this->cn->gen_key_derivation( $R, $view_key );
					$owned      = ( $this->cn->derive_public_key( $derivation, $i, $C_spend ) === $out_key );
				} catch ( \Throwable $e ) {
					continue;
				}
				if ( ! $owned ) { continue; }

				try {
					$commitment    = $this->outpk_mask( $outpk, $i );
					if ( in_array( $tx['rct_signatures']['type'] ?? null, array( 1, 2, 3 ), true ) ) {
						$decoded = $this->decode_legacy_amount( $derivation, $i, $ecdh[ $i ] ?? null );
						$amount_atomic = $decoded['amount_atomic'];
						$commitment_ok = $commitment ? $this->check_commitment_with_mask( $amount_atomic, $decoded['mask'], $commitment ) : false;
					} else {
						$amt_hex = isset( $ecdh[ $i ]['amount'] ) ? $ecdh[ $i ]['amount'] : '';
						$amount_atomic = '' !== $amt_hex ? $this->decode_amount( $derivation, $i, $amt_hex ) : '0';
						$commitment_ok = $commitment ? $this->check_commitment( $amount_atomic, $derivation, $i, $commitment ) : false;
					}
					$matches[] = array(
						'output_index'  => $i,
						'amount_atomic' => $amount_atomic,
						'out_key'       => $out_key,

						'commitment_present' => ( '' !== (string) $commitment && null !== $commitment ),
						'commitment_ok' => $commitment_ok,
					);
				} catch ( \Throwable $e ) {

					$matches[] = array(
						'output_index'      => $i,
						'amount_atomic'     => '0',
						'out_key'           => $out_key,
						'commitment_present' => false,
						'commitment_ok'     => false,
						'errored'           => true,
					);
				}
				break;
			}
		}
		usort( $matches, function ( $a, $b ) { return $a['output_index'] <=> $b['output_index']; } );
		return $this->budget_exhausted() ? array() : $matches;
	}

	/** Classic detection is atomic; block scans resume between transactions. */
	private function scan_transaction_chunk( $tx, $address, $view_key ) {
		$this->unsupported_outputs = 0;
		$vout = $tx['vout'] ?? array();
		$matches = $this->detect_all_in_tx( $tx, $address, $view_key );
		return array( 'matches' => $matches, 'complete' => true, 'next_output' => count( $vout ), 'readable' => $this->unsupported_outputs === 0 );
	}

	private static function canonical_evidence( $value ) {
		if ( ! is_array( $value ) ) { return $value; }
		ksort( $value );
		foreach ( $value as $key => $child ) { $value[$key] = self::canonical_evidence( $child ); }
		return $value;
	}

	private static function transaction_evidence_hash( $tx ) {
		$evidence = array( $tx['version'] ?? null, $tx['vin'] ?? array(), $tx['extra'] ?? array(), $tx['vout'] ?? array(),
			$tx['rct_signatures']['type'] ?? null, $tx['rct_signatures']['ecdhInfo'] ?? array(),
			$tx['rct_signatures']['outPk'] ?? ( $tx['rctsig_prunable']['outPk'] ?? array() ),
			$tx['unlock_time'] ?? 0, $tx['_block_height'] ?? null, ! empty( $tx['_in_pool'] ), ! empty( $tx['_double_spend_seen'] ) );
		$json = json_encode( self::canonical_evidence( $evidence ), JSON_PRESERVE_ZERO_FRACTION );
		return $json === false ? null : hash( 'sha256', $json );
	}


	private function classify_tx( $tx, $address, $view_key, $tip, $require_commitment ) {
		$m = $this->detect_in_tx( $tx, $address, $view_key );
		if ( $this->budget_exhausted() ) { return array( 'found' => false, 'budget_exhausted' => true, 'reason' => 'time budget exhausted' ); }
		if ( null === $m ) { return array( 'found' => false, 'unsupported_outputs' => $this->unsupported_outputs, 'reason' => $this->unsupported_outputs ? 'unsupported output format' : 'no output to this address' ); }
		return $this->classify_match( $m, $tx, $tip, $require_commitment );
	}

	private function classify_match( $m, $tx, $tip, $require_commitment ) {
		$bh   = isset( $tx['_block_height'] ) ? $tx['_block_height'] : null;
		$conf = ( null !== $bh && null !== $tip && $bh > 0 ) ? max( 0, $tip - $bh ) : ( ! empty( $tx['_in_pool'] ) ? 0 : null );
		$result = array(
			'found'         => true,
			'txid'          => $tx['_txid'] ?? '',
			'block_height'  => $tx['_block_height'] ?? null,
			'amount_atomic' => $m['amount_atomic'],
			'output_index'  => $m['output_index'],
			'confirmations' => $conf,
			'in_pool'       => ! empty( $tx['_in_pool'] ),
			'double_spend_seen' => ! empty( $tx['_double_spend_seen'] ),
			'unlock_time'   => $tx['unlock_time'] ?? 0,
			'locked'        => self::is_locked( $tx['unlock_time'] ?? 0, $tip ),
			'out_key'       => isset( $m['out_key'] ) ? $m['out_key'] : '',
			'commitment_ok' => $m['commitment_ok'],
			'commitment_present' => ! empty( $m['commitment_present'] ),
			'reason'        => 'ok',
		);
		if ( $require_commitment && empty( $m['commitment_ok'] ) ) {
			$result['reason'] = $result['commitment_present']
				? 'commitment mismatch: decoded amount not committed on-chain'
				: 'commitment unavailable: the node may be pruned; use a full (non-pruned) node';
		}
		return $result;
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

	/** First-match compatibility API, using the same complete-block rules as scan_all. */
	public function scan( $address, $view_key, $from_height, $to_height, $opts = array() ) {
		$result = $this->scan_all( $address, $view_key, $from_height, $to_height, $opts );
		if ( $result['matches'] ) {
			$match = $result['matches'][0];
			unset( $result['matches'] );
			return $match + array( 'found' => true ) + $result;
		}
		unset( $result['matches'] );
		return array( 'found' => false ) + $result;
	}

	/** Scan all owned outputs; checkpoint hashes are optional adapter-owned continuity evidence. */
	public function scan_all( $address, $view_key, $from_height, $to_height, $opts = array() ) {
		$this->reset_node_error();
		$previous_deadline = $this->deadline;
		$budget = isset( $opts['time_budget'] ) ? (float) $opts['time_budget'] : 8.0;
		$this->set_time_budget( $budget );
		if ( $previous_deadline !== null ) { $this->deadline = min( $this->deadline, $previous_deadline ); }
		try {
			$result = $this->scan_all_budgeted( $address, $view_key, $from_height, $to_height, $opts );
			$result['budget_exhausted'] = $this->budget_exhausted();
			if ( ! empty( $result['checkpoint_error'] ) ) { unset( $result['partial_block'] ); }
			if ( $result['budget_exhausted'] ) {
				$result['matches'] = array();
				$result['scanned_to'] = (int) $from_height - 1;
				$result['checkpoint'] = null;
				unset( $result['partial_block'] );
				$result['checkpoint_error'] = 'budget-exhausted';
			}
			return $this->scan_diagnostics( $result, (int) $from_height, (int) $to_height );
		} finally {
			$this->deadline = $previous_deadline;
		}
	}

	private function scan_diagnostics( $result, $from, $to ) {
		$result['node_error'] = $result['node_error'] ?? $this->last_node_error();
		$status = $result['scan_status'] ?? null;
		if ( ! empty( $result['budget_exhausted'] ) ) { $status = 'budget-exhausted'; }
		elseif ( ! empty( $result['reorg_detected'] ) ) { $status = 'reorg-detected'; }
		elseif ( ( $result['checkpoint_error'] ?? '' ) === 'invalid' ) { $status = 'invalid-context'; }
		elseif ( ! empty( $result['unsupported_outputs'] ) ) { $status = 'unverifiable-outputs'; }
		elseif ( $result['node_error']['code'] === 'node-disagreement' ) { $status = 'node-disagreement'; }
		elseif ( ! empty( $result['checkpoint_error'] ) ) { $status = 'unavailable'; }
		if ( $status === null ) {
			$checkpoint = $result['checkpoint'] ?? null;
			if ( is_array( $checkpoint ) && $checkpoint['height'] === $result['scanned_to']
				&& $result['scanned_to'] >= $to && empty( $result['partial_block'] ) ) { $status = 'complete'; }
			else { $status = $from > $to ? 'waiting-blocks' : 'incomplete'; }
		}
		$result['scan_status'] = $status;
		$result['scan_complete'] = $status === 'complete';
		return $result;
	}

	private function scan_all_budgeted( $address, $view_key, $from_height, $to_height, $opts ) {
		$max_blocks = isset( $opts['max_blocks'] ) ? max( 1, (int) $opts['max_blocks'] ) : 30;
		$require = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$tip = isset( $opts['tip'] ) ? (int) $opts['tip'] : (int) $to_height;
		$from = (int) $from_height;
		$result = array( 'matches' => array(), 'scanned_to' => $from - 1, 'unsupported_outputs' => 0, 'checkpoint' => null, 'reorg_detected' => false );
		$partial = $opts['partial_block'] ?? null;
		$pending_transaction = is_array( $partial ) ? ( $partial['transaction'] ?? null ) : null;
		$identity = hash( 'sha256', $address . ':' . $view_key );
		if ( $partial !== null && ( ! is_array( $partial ) || ( $partial['identity'] ?? null ) !== $identity
			|| ( $partial['height'] ?? null ) !== $from || ! is_string( $partial['hash'] ?? null )
			|| ! preg_match( '/^[0-9a-f]{64}$/D', $partial['hash'] )
			|| ! is_string( $partial['transaction_list_hash'] ?? null )
			|| ! is_int( $partial['next_transaction'] ?? null ) || $partial['next_transaction'] < 0
			|| ! is_array( $partial['matches'] ?? null ) ) ) {
			$result['checkpoint_error'] = 'invalid';
			return $result;
		}
		if ( $pending_transaction !== null && ( ! is_array( $pending_transaction )
			|| ! is_string( $pending_transaction['txid'] ?? null ) || ! preg_match( '/^[0-9a-f]{64}$/D', $pending_transaction['txid'] )
			|| ! is_string( $pending_transaction['evidence_hash'] ?? null ) || ! preg_match( '/^[0-9a-f]{64}$/D', $pending_transaction['evidence_hash'] )
			|| ! is_int( $pending_transaction['next_output'] ?? null ) || $pending_transaction['next_output'] < 0 || $pending_transaction['next_output'] >= 256 ) ) {
			$result['checkpoint_error'] = 'invalid';
			return $result;
		}
		if ( isset( $opts['checkpoint'] ) ) {
			$failure = $this->check_checkpoint( $opts, $result );
			if ( $failure !== null ) { return $failure; }
			$result['checkpoint'] = $opts['checkpoint'];
		}
		$acquired = array();
		$previous = isset( $opts['checkpoint'] ) && $opts['checkpoint']['height'] === $from - 1 ? $opts['checkpoint']['hash'] : null;
		// Keep half the remaining budget for final anchor and acquired-header validation.
		$acquisition_end = hrtime( true ) / 1000000000 + $this->remaining_time() / 2;
		$last_block_duration = 0.0;
		$end = min( (int) $to_height, $from + $max_blocks - 1 );
		for ( $height = $from; $height <= $end; $height++ ) {
			$block_started = hrtime( true ) / 1000000000;
			if ( $block_started + $last_block_duration >= $acquisition_end ) { break; }
			$hashes = $this->block_tx_hashes( $height );
			if ( $hashes === null ) {
				$result['scan_status'] = 'unavailable';
				$result['node_error'] = $this->last_node_error();
				if ( isset( $opts['partial_block'] ) ) { $result['checkpoint_error'] = 'unavailable'; }
				break;
			}
			$block_hash = $this->last_block_hash;
			if ( $previous !== null && $this->last_previous_hash !== null && $previous !== $this->last_previous_hash ) {
				return $this->reorg_result( $opts, $from - 1 );
			}
			$previous = $block_hash;
			if ( $block_hash !== null ) { $acquired[$height] = $block_hash; }
			$block_matches = array();
			$incomplete = false;
			$next_transaction = 0;
			$list_hash = hash( 'sha256', implode( '', $hashes ) );
			if ( $partial !== null ) {
				if ( $partial['hash'] !== $block_hash || $partial['transaction_list_hash'] !== $list_hash ) {
					return $this->reorg_result( $opts, $from - 1 );
				}
				if ( $partial['next_transaction'] >= count( $hashes ) ) { $result['checkpoint_error'] = 'invalid'; return $result; }
				$next_transaction = $partial['next_transaction'];
				$block_matches = $partial['matches'];
				foreach ( $block_matches as &$match ) {
					$match['confirmations'] = max( 0, $tip - $height );
					$match['locked'] = self::is_locked( $match['unlock_time'] ?? null, $tip );
				}
				unset( $match );
				$partial = null;
			}
			$paused = false;
			foreach ( array_chunk( array_slice( $hashes, $next_transaction ), 10 ) as $batch ) {
				if ( hrtime( true ) / 1000000000 >= $acquisition_end ) { $paused = true; break; }
				$transactions = $this->fetch_txs( $batch );
				if ( $transactions === null ) {
					$result['scan_status'] = 'unavailable';
					$result['node_error'] = $this->last_node_error();
					if ( isset( $opts['partial_block'] ) ) {
						$result['checkpoint_error'] = 'unavailable';
						return $this->finish_scan( $opts, $result, $acquired, $from );
					}
					$incomplete = true;
					continue;
				}
				// Daemons may return a batch in any order; the cursor follows the block's list.
				$by_hash = array();
				foreach ( $transactions as $tx ) { $by_hash[$tx['_txid']] = $tx; }
				foreach ( $batch as $txid ) {
					if ( ! isset( $by_hash[$txid] ) ) { $incomplete = true; break 2; }
					$tx = $by_hash[$txid];
					if ( hrtime( true ) / 1000000000 >= $acquisition_end ) { $paused = true; break 2; }
					if ( $this->budget_exhausted() ) { return $result; }
					$start_output = 0;
					$evidence_hash = self::transaction_evidence_hash( $tx );
					if ( $pending_transaction !== null ) {
						if ( $pending_transaction['txid'] !== $txid || $pending_transaction['evidence_hash'] !== $evidence_hash ) {
							return $this->reorg_result( $opts, $from - 1 );
						}
						$start_output = $pending_transaction['next_output'];
						if ( $start_output >= count( $tx['vout'] ?? array() ) ) { $result['checkpoint_error'] = 'invalid'; return $result; }
					}
					if ( ! empty( $tx['_in_pool'] ) || ! isset( $tx['_block_height'] ) || (int) $tx['_block_height'] !== $height ) {
						$result['scan_status'] = 'inconsistent-data';
						$incomplete = true;
						continue;
					}
					$chunk = $this->scan_transaction_chunk( $tx, $address, $view_key );
					if ( $this->budget_exhausted() ) { return $result; }
					$result['unsupported_outputs'] += $this->unsupported_outputs;
					if ( $this->unsupported_outputs ) { $incomplete = true; }
					if ( ! $chunk['readable'] ) {
						// An unreadable later enote invalidates this transaction's earlier chunks.
						$retained = array();
						foreach ( $block_matches as $row ) {
							if ( $row['txid'] !== $txid ) { $retained[] = $row; }
						}
						$block_matches = $retained;
					}
					foreach ( $chunk['matches'] as $match ) {
						if ( $require && empty( $match['commitment_ok'] ) ) {
							$result['scan_status'] = 'unverified-commitment';
							$incomplete = true;
							continue;
						}
						$row = $this->classify_match( $match, $tx, max( $tip, $height ), $require );
						unset( $row['found'], $row['reason'] );
						$row['block_hash'] = $block_hash;
						$block_matches[] = $row;
					}
					if ( ! $chunk['complete'] && $chunk['readable'] ) {
						if ( $evidence_hash !== null && $chunk['next_output'] > 0 ) {
							$pending_transaction = array( 'txid' => $txid, 'evidence_hash' => $evidence_hash, 'next_output' => $chunk['next_output'] );
						}
						$paused = true;
						break 2;
					}
					$pending_transaction = null;
					$next_transaction++;
				}
			}
			// Recheck the canonical header after acquisition; never mix branches in one result.
			if ( $block_hash !== null ) {
				$again = $this->block_tx_hashes( $height );
				if ( $again === null ) { return $this->finish_scan( $opts, $result, $acquired, $from ); }
				if ( $this->last_block_hash !== $block_hash || $again !== $hashes ) {
					return $this->reorg_result( $opts, $from - 1 );
				}
			}
			if ( $incomplete ) {
				$result['matches'] = array_merge( $result['matches'], $block_matches );
				return $this->finish_scan( $opts, $result, $acquired, $from );
			}
			if ( $paused ) {
				if ( $block_hash !== null && ( $next_transaction > 0 || $pending_transaction !== null ) ) {
					$result['partial_block'] = array( 'identity' => $identity, 'height' => $height, 'hash' => $block_hash,
						'transaction_list_hash' => $list_hash, 'next_transaction' => $next_transaction, 'matches' => $block_matches );
					if ( $pending_transaction !== null ) { $result['partial_block']['transaction'] = $pending_transaction; }
				}
				return $this->finish_scan( $opts, $result, $acquired, $from );
			}
			$result['matches'] = array_merge( $result['matches'], $block_matches );
			$last_block_duration = hrtime( true ) / 1000000000 - $block_started;
			$result['scanned_to'] = $height;
			$result['checkpoint'] = $block_hash === null ? null : array( 'height' => $height, 'hash' => $block_hash );
		}
		return $this->finish_scan( $opts, $result, $acquired, $from );
	}

	private function finish_scan( $opts, $result, $acquired, $from ) {
		// Every exit revalidates the caller's anchor, including incomplete acquisition.
		if ( isset( $opts['checkpoint'] ) ) {
			$failure = $this->check_checkpoint( $opts, $result );
			if ( $failure !== null ) { return $failure; }
		}
		foreach ( $acquired as $height => $hash ) {
			if ( $this->block_tx_hashes( $height ) === null || $this->last_block_hash === null ) {
				$result['matches'] = array();
				$result['scanned_to'] = $from - 1;
				$result['checkpoint'] = null;
				$result['checkpoint_error'] = 'unavailable';
				unset( $result['partial_block'] );
				return $result;
			}
			if ( $this->last_block_hash !== $hash ) { return $this->reorg_result( $opts, $from - 1 ); }
		}
		return $result;
	}

	private function check_checkpoint( $opts, $result ) {
		$checkpoint = $opts['checkpoint'];
		if ( ! is_array( $checkpoint ) || ! isset( $checkpoint['height'], $checkpoint['hash'] ) || ! is_int( $checkpoint['height'] ) || $checkpoint['height'] < 0 || ! is_string( $checkpoint['hash'] ) || ! preg_match( '/^[0-9a-f]{64}$/D', $checkpoint['hash'] ) ) {
			$result['matches'] = array(); $result['checkpoint_error'] = 'invalid'; return $result;
		}
		if ( $this->block_tx_hashes( $checkpoint['height'] ) === null || $this->last_block_hash === null ) {
			$result['matches'] = array();
			$result['scanned_to'] = min( $result['scanned_to'], $checkpoint['height'] );
			$result['checkpoint'] = null;
			$result['checkpoint_error'] = 'unavailable';
			return $result;
		}
		if ( $checkpoint['hash'] !== $this->last_block_hash ) {
			return $this->reorg_result( $opts, (int) ( $opts['restore_height'] ?? ( $checkpoint['height'] + 1 ) ) - 1 );
		}
		return null;
	}

	private function reorg_result( $opts, $last ) {
		$restore = isset( $opts['restore_height'] ) && is_int( $opts['restore_height'] ) && $opts['restore_height'] >= 0 ? $opts['restore_height'] : null;
		return array( 'matches' => array(), 'scanned_to' => $restore === null ? $last : $restore - 1, 'unsupported_outputs' => 0, 'checkpoint' => null, 'reorg_detected' => true, 'rescan_from' => $restore );
	}

	private function outpk_mask( $outpk, $i ) {
		if ( ! isset( $outpk[ $i ] ) ) { return null; }
		$v = $outpk[ $i ];
		if ( is_string( $v ) ) { return $v; }
		if ( is_array( $v ) && isset( $v['mask'] ) ) { return $v['mask']; }
		return null;
	}

	public static function is_locked( $unlock_time, $tip ) {
		if ( ! is_int( $unlock_time ) || $unlock_time < 0 ) {
			return true;
		}
		$ut = $unlock_time;
		if ( 0 === $ut ) { return false; }
		if ( $ut < 500000000 ) {
			if ( null === $tip ) { return true; }
			return $ut > ( $tip - 1 );
		}
		return $ut > ( time() - 1 );
	}
}
