<?php

namespace XmrPay;

/**
 * Scanner — non-custodial Monero verification, in pure PHP.
 *
 * Detects a payment to a watched address/subaddress and decodes its amount using ONLY
 * public on-chain data fetched from a public node (daemon RPC over HTTP) plus the
 * merchant's PRIVATE VIEW KEY (which lives only on their own WP server — non-custodial;
 * we never hold a spend key). No Node, no WASM, no monero-wallet-rpc, no external service.
 *
 * The crypto stands on the vendored, audited primitives in vendor/monero/ and was
 * cross-checked against monero-ts on real stagenet payments (see
 * docs/WP-NATIVE-VERIFICATION.md). Four independent guards make a detected payment real:
 *   1. ownership   — the output's one-time key equals Hs(8·a·R, i)·G + C  (only the view
 *                    key + the recipient address can produce this) → the output is ours.
 *   2. amount      — RingCT decode: amount = ecdhInfo XOR first8(keccak("amount"||Hs(D,i))).
 *   3. commitment  — C_chain == amount·H + mask·G  (mask deterministic) → the decoded
 *                    amount is the REAL committed amount, not a forged ecdh value.
 *   4. unlock/conf — unlock_time elapsed + enough confirmations → spendable, settled.
 *
 * Requires BOTH the GMP and BCMath PHP extensions: the money math is GMP-only and the
 * vendored base58 (decode_address) is BCMath-only. ed25519 prefers GMP for speed.
 */


use MoneroIntegrations\MoneroPhp\Cryptonote;

class Scanner {

	/** Monero's second generator H (rct), compressed point hex — a fixed protocol constant. */
	const H_POINT = '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94';

	private $node;
	private $nodes;
	private $cn;
	private $http_timeout;
	private $network;

	/**
	 * $network ('mainnet'|'stagenet'|'testnet') only affects subaddress STRING generation
	 * (the address prefix/checksum). Detection (decode_address) is network-agnostic, so an
	 * unset/wrong network never causes a false positive — it would only mint a wrong
	 * address string. Defaults to mainnet.
	 */
	public function __construct( $node, $network = 'mainnet', $http_timeout = 20 ) {
		// $node is one URL or a comma-separated list. The extras give node_rpc FAILOVER (try each
		// until one answers) and a conservative tip_height CROSS-CHECK (min height across
		// responders) — so a lagging or lying node can only DELAY settlement, never bring it
		// forward. Heavy calls (tx fetch, get_block) inherit failover via node_rpc/json_rpc.
		$list               = is_array( $node ) ? $node : explode( ',', (string) $node );
		$this->nodes        = array_values( array_filter( array_map( function ( $u ) { return rtrim( trim( (string) $u ), '/' ); }, $list ) ) );
		$this->node         = $this->nodes ? $this->nodes[0] : '';
		$this->http_timeout = (int) $http_timeout;
		$this->network      = in_array( $network, array( 'mainnet', 'stagenet', 'testnet' ), true ) ? $network : 'mainnet';
		$this->cn           = new Cryptonote( $this->network );
	}

	/* ------------------------------------------------------------------ *
	 *  HTTP — uses wp_remote_post under WordPress, a stream fallback in tests
	 * ------------------------------------------------------------------ */
	private function node_rpc( $path, $body ) {
		// FAILOVER: try each configured node until one answers. json_rpc() routes through here, so
		// get_block / get_info inherit failover too. The commitment check validates tx data
		// regardless of which node served it, so a failover source can't forge a payment.
		foreach ( $this->nodes as $node ) {
			$r = $this->node_rpc_one( $node, $path, $body );
			if ( null !== $r ) { return $r; }
		}
		return null;
	}

	private function node_rpc_one( $node, $path, $body ) {
		$url     = $node . $path;
		$payload = function_exists( 'wp_json_encode' ) ? wp_json_encode( $body ) : json_encode( $body );
		if ( function_exists( 'wp_safe_remote_post' ) ) {
			$res = wp_safe_remote_post( $url, array(
				'timeout'             => $this->http_timeout,
				'headers'             => array( 'Content-Type' => 'application/json' ),
				'body'                => $payload,
				'limit_response_size' => 4 * 1024 * 1024, // 4 MB — a real Monero RPC response is ≤ 1 MB
			) );
			if ( is_wp_error( $res ) ) {
				return null;
			}
			$code = (int) wp_remote_retrieve_response_code( $res );
			if ( $code < 200 || $code >= 300 ) {
				return null;
			}
			$raw = wp_remote_retrieve_body( $res );
			if ( strlen( $raw ) > 4 * 1024 * 1024 ) { return null; }
			return json_decode( $raw, true );
		}
		// non-WP host (Joomla, plain PHP, tests)
		$raw = $this->http_raw( $url, $payload );
		if ( null === $raw || strlen( $raw ) > 4 * 1024 * 1024 ) { return null; }
		return json_decode( $raw, true );
	}

	// non-WP transport. curl first so it works where allow_url_fopen is Off (common on hardened
	// shared hosts), with a stream-wrapper fallback. restricted to http(s) so file:// / data: can
	// never reach the filesystem, even under XMRPAY_TESTING. returns the raw body or null.
	private function http_raw( $url, $payload = null ) {
		if ( ! in_array( strtolower( (string) parse_url( $url, PHP_URL_SCHEME ) ), array( 'http', 'https' ), true ) ) {
			return null;
		}
		if ( function_exists( 'curl_init' ) ) {
			$ch = curl_init( $url );
			curl_setopt_array( $ch, array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_TIMEOUT        => $this->http_timeout,
				CURLOPT_CONNECTTIMEOUT => $this->http_timeout,
				CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
				CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
			) );
			if ( null !== $payload ) {
				curl_setopt( $ch, CURLOPT_POST, true );
				curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
				curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'Content-Type: application/json' ) );
			}
			$raw  = curl_exec( $ch );
			$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
			curl_close( $ch );
			// curl is present: trust its verdict (a failed request fails over to the next node),
			// never fall through to a transport that needs allow_url_fopen.
			return ( $raw !== false && $code >= 200 && $code < 300 ) ? $raw : null;
		}
		$opts = array( 'timeout' => $this->http_timeout, 'ignore_errors' => true );
		if ( null !== $payload ) {
			$opts['method']  = 'POST';
			$opts['header']  = "Content-Type: application/json\r\n";
			$opts['content'] = $payload;
		}
		$ctx = stream_context_create( array( 'http' => $opts ) );
		$raw = @file_get_contents( $url, false, $ctx );
		return $raw === false ? null : $raw;
	}

	/** Fetch + decode a BATCH of transactions. Returns an array of as_json arrays (each with
	 *  _txid/_block_height/_in_pool), or null on a node failure. Empty input → []. */
	public function fetch_txs( $txids ) {
		$txids = array_values( array_filter( (array) $txids ) );
		if ( ! $txids ) { return array(); }
		$resp = $this->node_rpc( '/get_transactions', array( 'txs_hashes' => $txids, 'decode_as_json' => true ) );
		if ( ! $resp || ! isset( $resp['txs'] ) || ! is_array( $resp['txs'] ) ) { return null; }
		$out = array();
		foreach ( $resp['txs'] as $tx ) {
			$asjson = isset( $tx['as_json'] ) ? json_decode( $tx['as_json'], true ) : null;
			if ( ! is_array( $asjson ) ) { continue; }
			$asjson['_txid']         = isset( $tx['tx_hash'] ) ? $tx['tx_hash'] : '';
			$asjson['_block_height'] = isset( $tx['block_height'] ) ? (int) $tx['block_height'] : null;
			$asjson['_in_pool']      = ! empty( $tx['in_pool'] );
			// the daemon forces this false for on-chain txs and only sets it true for a MEMPOOL tx
			// whose key images conflict with another pool tx — i.e. a visible double-spend attempt.
			// only meaningful while in_pool; carried so the 0-conf credit path can refuse it.
			$asjson['_double_spend_seen'] = ! empty( $tx['double_spend_seen'] );
			$out[] = $asjson;
		}
		return $out;
	}

	/** Fetch + decode ONE transaction. Returns the as_json array or null. */
	public function fetch_tx( $txid ) {
		$txs = $this->fetch_txs( array( $txid ) );
		if ( ! is_array( $txs ) || ! isset( $txs[0] ) ) { return null; }
		// cross-check: reject a node that returns a different tx than requested.
		if ( strcasecmp( (string) $txs[0]['_txid'], (string) $txid ) !== 0 ) { return null; }
		return $txs[0];
	}

	/** Monero daemon json_rpc call (POST /json_rpc). Returns the `result` array or null. */
	private function json_rpc( $method, $params = array() ) {
		$r = $this->node_rpc( '/json_rpc', array( 'jsonrpc' => '2.0', 'id' => '0', 'method' => $method, 'params' => $params ) );
		return ( is_array( $r ) && isset( $r['result'] ) ) ? $r['result'] : null;
	}

	/**
	 * Setup check: does this PRIVATE VIEW key actually belong to this address? Derives the
	 * public view key from the private one and compares it to the address — catching the #1
	 * misconfiguration (a view key pasted for the wrong wallet), which would otherwise just
	 * silently detect nothing. Returns ['address_valid'=>bool, 'key_match'=>bool].
	 */
	public function verify_keys( $address, $view_key ) {
		try {
			$dec = $this->cn->decode_address( $address );   // throws on a malformed address
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

	/**
	 * Is this a structurally valid Monero address? Decodes base58 + verifies the checksum
	 * (network-agnostic: standard, subaddress, and integrated all pass). Offline — no node
	 * call. Used to validate a buyer-supplied refund address before the merchant sends. Never
	 * throws; returns false on anything malformed.
	 */
	public function address_valid( $address ) {
		try {
			$dec = $this->cn->decode_address( (string) $address );   // throws on bad base58 / checksum
		} catch ( \Throwable $e ) {
			return false;
		}
		if ( empty( $dec['viewKey'] ) || empty( $dec['spendKey'] ) ) {
			return false;
		}
		// NETWORK GATE: the prefix MUST belong to THIS store's network, so a buyer cannot submit a
		// valid-checksum address from the WRONG network (e.g. a stagenet address on a mainnet store).
		// Such an address is unpayable — the merchant's wallet would refuse it — and sending to it
		// would lose the refund. Bytes mirror the vendored Cryptonote network_prefixes (standard,
		// integrated, subaddress per network).
		$valid = array(
			'mainnet'  => array( '12', '13', '2a' ),   // 18, 19, 42
			'stagenet' => array( '18', '19', '24' ),   // 24, 25, 36
			'testnet'  => array( '35', '36', '3f' ),   // 53, 54, 63
		);
		$allowed = isset( $valid[ $this->network ] ) ? $valid[ $this->network ] : $valid['mainnet'];
		$byte    = isset( $dec['networkByte'] ) ? strtolower( (string) $dec['networkByte'] ) : '';
		return in_array( $byte, $allowed, true );
	}

	/** Node reachability + network. Returns ['ok'=>bool,'height'=>int|null,'nettype'=>string]. */
	public function node_info() {
		$r = $this->node_rpc_get_one( $this->node, '/get_info' );
		if ( is_array( $r ) ) {
			$nettype = isset( $r['nettype'] ) ? (string) $r['nettype']
				: ( ! empty( $r['stagenet'] ) ? 'stagenet' : ( ! empty( $r['testnet'] ) ? 'testnet' : 'mainnet' ) );
			return array( 'ok' => true, 'height' => isset( $r['height'] ) ? (int) $r['height'] : null, 'nettype' => $nettype );
		}
		$h = $this->tip_height();   // fall back to /get_height (restricted nodes)
		return null === $h ? array( 'ok' => false, 'height' => null, 'nettype' => 'unknown' )
			: array( 'ok' => true, 'height' => $h, 'nettype' => 'unknown' );
	}

	/** The non-coinbase tx hashes in a block at $height. Returns array (maybe empty) or null on error. */
	private function block_tx_hashes( $height ) {
		$r = $this->json_rpc( 'get_block', array( 'height' => (int) $height ) );
		if ( null === $r ) { return null; }
		return isset( $r['tx_hashes'] ) && is_array( $r['tx_hashes'] ) ? $r['tx_hashes'] : array();
	}

	public function tip_height() {
		// CROSS-CHECK: ask every configured node and take the MINIMUM height among responders.
		// confirmations = tip - tx_height, so the lowest tip yields the fewest confirmations — a
		// node that is behind or lying can only DELAY settlement, never accelerate it. null if no
		// node answered (the caller — scan_order / verify — then declines to act on stale data).
		$heights = array();
		foreach ( $this->nodes as $node ) {
			$r = $this->node_rpc_get_one( $node, '/get_height' );
			if ( $r && isset( $r['height'] ) && (int) $r['height'] > 0 ) { $heights[] = (int) $r['height']; }
		}
		return $heights ? min( $heights ) : null;
	}
	private function node_rpc_get_one( $node, $path ) {
		$url = $node . $path;
		if ( function_exists( 'wp_safe_remote_get' ) ) {
			$res = wp_safe_remote_get( $url, array(
				'timeout'             => $this->http_timeout,
				'limit_response_size' => 4 * 1024 * 1024,
			) );
			if ( is_wp_error( $res ) ) { return null; }
			$raw = wp_remote_retrieve_body( $res );
			if ( strlen( $raw ) > 4 * 1024 * 1024 ) { return null; }
			return json_decode( $raw, true );
		}
		$raw = $this->http_raw( $url );
		if ( null === $raw || strlen( $raw ) > 4 * 1024 * 1024 ) { return null; }
		return json_decode( $raw, true );
	}

	/* ------------------------------------------------------------------ *
	 *  tx_extra parsing — main tx pubkey (tag 01) + additional pubkeys (tag 04)
	 * ------------------------------------------------------------------ */
	private function parse_extra( $extra_bytes ) {
		$n = count( $extra_bytes ); $pos = 0; $main = null; $additional = array();
		while ( $pos < $n ) {
			$tag = $extra_bytes[ $pos++ ];
			if ( 1 === $tag ) {
				$main = $this->take_hex( $extra_bytes, $pos, 32, $n );
				if ( null === $main ) { break; }                     // truncated — stop, don't read past the end
			} elseif ( 2 === $tag ) {
				$len = $this->read_varint( $extra_bytes, $pos, $n );
				$pos = min( $n, $pos + $len );                       // nonce/payment-id — clamp, never overshoot
			} elseif ( 4 === $tag ) {
				$cnt = min( $this->read_varint( $extra_bytes, $pos, $n ), 256 ); // a valid tx has ≤ output-count keys
				for ( $k = 0; $k < $cnt; $k++ ) {
					$h = $this->take_hex( $extra_bytes, $pos, 32, $n );
					if ( null === $h ) { break 2; }                  // truncated additional list — stop
					$additional[] = $h;
				}
			} elseif ( 0 === $tag ) {
				break; // padding — rest is zeros
			} else {
				break; // unknown tag — stop rather than misparse
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
		if ( null !== $n && $pos + $len > $n ) { $pos = $n; return null; }   // would read past the buffer
		$h = '';
		for ( $k = 0; $k < $len; $k++ ) { $h .= str_pad( dechex( (int) $b[ $pos++ ] ), 2, '0', STR_PAD_LEFT ); }
		return $h;
	}

	/* ------------------------------------------------------------------ *
	 *  amount + commitment
	 * ------------------------------------------------------------------ */
	private function le8_to_dec( $hex8 ) {
		$v = gmp_init( 0 ); $bs = str_split( $hex8, 2 );
		for ( $k = count( $bs ) - 1; $k >= 0; $k-- ) { $v = gmp_add( gmp_mul( $v, 256 ), gmp_init( hexdec( $bs[ $k ] ), 10 ) ); }
		return gmp_strval( $v );
	}
	/** RingCT 8-byte amount decode: ecdhInfo[i].amount XOR first8(keccak("amount"||Hs(D,i))). */
	private function decode_amount( $derivation, $i, $ecdh_hex ) {
		$sk     = $this->cn->derivation_to_scalar( $derivation, $i );
		$factor = $this->cn->keccak_256( bin2hex( 'amount' ) . $sk );
		$mask8  = substr( $factor, 0, 16 );
		$amt    = strlen( $ecdh_hex ) >= 16 ? substr( $ecdh_hex, 0, 16 ) : str_pad( $ecdh_hex, 16, '0' );
		return $this->le8_to_dec( bin2hex( hex2bin( $amt ) ^ hex2bin( $mask8 ) ) );
	}
	/**
	 * Commitment check: the decoded amount is the REAL committed amount iff
	 * C_chain == amount·H + mask·G, with the deterministic mask = Hs("commitment_mask"||Hs(D,i)).
	 * This stops a crafted ecdhInfo from decoding to a fake (larger) amount.
	 */
	public function check_commitment( $amount_atomic, $derivation, $i, $commitment_hex ) {
		if ( '' === (string) $commitment_hex || null === $commitment_hex ) {
			return false; // no commitment to check against → fail closed
		}
		$ed   = $this->cn_ed();
		$sk   = $this->cn->derivation_to_scalar( $derivation, $i );
		$mask = $this->cn->hash_to_scalar( bin2hex( 'commitment_mask' ) . $sk ); // deterministic mask (hex scalar)
		// amount·H
		$H    = $ed->decodepoint( hex2bin( self::H_POINT ) );
		$aH   = ( '0' === (string) $amount_atomic ) ? array( 0, 1 ) : $ed->scalarmult( $H, gmp_init( $amount_atomic, 10 ) );
		// mask·G
		$mG   = $ed->scalarmult_base( $ed->decodeint( hex2bin( $mask ) ) );
		$C    = bin2hex( $ed->encodepoint( $ed->edwards( $aH, $mG ) ) );
		return hash_equals( strtolower( (string) $commitment_hex ), strtolower( $C ) );
	}
	private function cn_ed() {
		// reach the vendored ed25519 instance the Cryptonote toolbox already holds.
		// it's a protected prop — setAccessible(true) is REQUIRED on PHP 7.4 / 8.0
		// (without it getValue() throws); on 8.1+ it's a harmless no-op.
		$ref = new \ReflectionProperty( get_class( $this->cn ), 'ed25519' );
		if ( \PHP_VERSION_ID < 80100 ) { $ref->setAccessible( true ); } // required <8.1; a deprecated no-op after
		return $ref->getValue( $this->cn );
	}

	/* ------------------------------------------------------------------ *
	 *  the verify
	 * ------------------------------------------------------------------ */
	/**
	 * Verify a payment to $address. Returns:
	 *   ['found'=>bool, 'amount_atomic'=>string, 'output_index'=>int, 'confirmations'=>int|null,
	 *    'in_pool'=>bool, 'locked'=>bool, 'commitment_ok'=>bool, 'reason'=>string]
	 * $view_key = merchant private view key (hex). $address = the order's address/subaddress.
	 */
	public function verify_payment( $txid, $address, $view_key, $opts = array() ) {
		$require_commitment = isset( $opts['require_commitment'] ) ? (bool) $opts['require_commitment'] : true;
		$tip                = isset( $opts['tip'] ) ? (int) $opts['tip'] : null;
		$tx = $this->fetch_tx( $txid );
		if ( ! $tx ) {
			return array( 'found' => false, 'reason' => 'node did not return the tx' );
		}
		return $this->classify_tx( $tx, $address, $view_key, $tip, $require_commitment );
	}

	/**
	 * Detect an output to $address inside one decoded tx and decode its amount. Returns
	 * ['output_index','amount_atomic','commitment_ok'] or null. Pure per-tx — the same a·R
	 * derivation works for any number of watched orders (caller computes it once per tx).
	 * Subaddresses are handled: the additional pubkey (tag 04) is tried before the main R.
	 */
	public function detect_in_tx( $tx, $address, $view_key ) {
		$dec = $this->cn->decode_address( $address );
		if ( empty( $dec['spendKey'] ) ) { return null; }
		$C_spend = $dec['spendKey'];
		$extra = $this->parse_extra( isset( $tx['extra'] ) ? $tx['extra'] : array() );
		$vout  = isset( $tx['vout'] ) ? $tx['vout'] : array();
		if ( count( $vout ) > 256 ) { return null; } // guard: a real Monero tx has ≤ 16 outputs; 256 is already generous
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
				// OWNERSHIP test only. A tx pubkey that is not a valid curve point (ed25519
				// decodepoint throws) is legitimately "not ours" — swallow and try the next
				// candidate so a single hostile tx in a scanned block can never abort the loop.
				try {
					$derivation = $this->cn->gen_key_derivation( $R, $view_key );
					$owned      = ( $this->cn->derive_public_key( $derivation, $i, $C_spend ) === $out_key );
				} catch ( \Throwable $e ) {
					continue;
				}
				if ( ! $owned ) { continue; }
				// OWNED. Decode amount + commitment OUTSIDE the ownership swallow: a failure here is
				// "ours but undecodable" (e.g. a pruned node, a malformed blob), NOT "not ours" — so
				// surface it as a fail-closed errored match (commitment_ok=false), never a silent miss
				// that would report the order unpaid. classify_tx then reports it found-but-unverified.
				try {
					$amt_hex       = isset( $ecdh[ $i ]['amount'] ) ? $ecdh[ $i ]['amount'] : '';
					$amount_atomic = '' !== $amt_hex ? $this->decode_amount( $derivation, $i, $amt_hex ) : '0';
					$commitment    = $this->outpk_mask( $outpk, $i );
					return array(
						'output_index'  => $i,
						'amount_atomic' => $amount_atomic,
						'out_key'       => $out_key,   // one-time output key (P): the burning-bug dedup key
						// distinguish "no commitment in the tx blob" (a PRUNED node) from "present but
						// doesn't match" (a real mismatch) — both fail closed, but the buyer/merchant
						// message differs (pruned → use a full node; mismatch → genuinely invalid).
						'commitment_present' => ( '' !== (string) $commitment && null !== $commitment ),
						'commitment_ok' => $commitment ? $this->check_commitment( $amount_atomic, $derivation, $i, $commitment ) : false,
					);
				} catch ( \Throwable $e ) {
					// ours, but the amount/commitment could not be decoded — fail closed + visible.
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

	/** Fold a per-tx match into the full result shape, adding confirmations + lock. */
	private function classify_tx( $tx, $address, $view_key, $tip, $require_commitment ) {
		$m = $this->detect_in_tx( $tx, $address, $view_key );
		if ( null === $m ) { return array( 'found' => false, 'reason' => 'no output to this address' ); }
		if ( $require_commitment && empty( $m['commitment_ok'] ) ) {
			$present = ! empty( $m['commitment_present'] );
			return array( 'found' => true, 'amount_atomic' => $m['amount_atomic'], 'output_index' => $m['output_index'], 'out_key' => isset( $m['out_key'] ) ? $m['out_key'] : '', 'commitment_ok' => false, 'commitment_present' => $present,
				'reason' => $present ? 'commitment mismatch — decoded amount not committed on-chain' : 'commitment unavailable — the node may be pruned; use a full (non-pruned) node' );
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

	/**
	 * Derive the per-order subaddress (account $major, index $minor) from the merchant's
	 * primary address + private view key — no spend secret needed. Returns
	 * ['address'=>string, 'spend_pub'=>hex]. (0,0) is the primary address itself.
	 */
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

	/**
	 * Watch-mode block scan: look for a payment to $address across blocks [from..to],
	 * BOUNDED by max_blocks and a wall-clock budget (so a shared-host request never blows
	 * max_execution_time). Returns the first match (found:true + txid + confirmations) or
	 * ['found'=>false, 'scanned_to'=>height] so the caller can checkpoint and resume.
	 */
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
			if ( null === $hashes ) { break; }                 // node hiccup — resume next tick
			foreach ( array_chunk( $hashes, 50 ) as $batch ) {
				$txs = $this->fetch_txs( $batch );
				if ( null === $txs ) { return array( 'found' => false, 'scanned_to' => $last ); }
				foreach ( $txs as $tx ) {
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
			$last = $h;
		}
		return array( 'found' => false, 'scanned_to' => $last );
	}

	/**
	 * Same bounded block scan as scan(), but collects EVERY matching payment in the
	 * window instead of returning the first. Returns ['matches'=>[ row, ... ], 'scanned_to'=>h]
	 * where each row is {txid, amount_atomic, confirmations, in_pool:false, locked, commitment_ok,
	 * block_height} — the shape XmrPay_Util::summarize_payments sums. Lets WP-native mode
	 * settle an order paid across multiple txs (installments / a test tx then the rest).
	 */
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
			if ( null === $hashes ) { break; }                 // node hiccup — resume next tick
			foreach ( array_chunk( $hashes, 50 ) as $batch ) {
				$txs = $this->fetch_txs( $batch );
				if ( null === $txs ) { return array( 'matches' => $matches, 'scanned_to' => $last ); }
				foreach ( $txs as $tx ) {
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
			$last = $h;
		}
		return array( 'matches' => $matches, 'scanned_to' => $last );
	}

	/** outPk[i] commitment as 32-byte hex (it may be a string or a {mask:...} object). */
	private function outpk_mask( $outpk, $i ) {
		if ( ! isset( $outpk[ $i ] ) ) { return null; }
		$v = $outpk[ $i ];
		if ( is_string( $v ) ) { return $v; }
		if ( is_array( $v ) && isset( $v['mask'] ) ) { return $v['mask']; }
		return null;
	}

	/**
	 * unlock_time gate (both Monero forms). <5e8 = block height; >=5e8 = unix time.
	 * Under-estimate the tip by 1 conf so we never report unlocked a hair early.
	 */
	private function is_locked( $unlock_time, $block_height, $conf, $tip ) {
		$ut = (int) $unlock_time;
		if ( 0 === $ut ) { return false; }
		if ( $ut < 500000000 ) {              // block-height form
			if ( null === $tip ) { return true; }
			return $ut > ( $tip - 1 );
		}
		return $ut > ( time() - 1 );          // timestamp form
	}
}
