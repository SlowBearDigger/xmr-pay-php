<?php
// Validate and calculate Monero amounts and payment state.

namespace XmrPay;

class Util {

	const XMR_DECIMALS = 12;

	public static function crypto_ready() {
		return extension_loaded( 'gmp' ) && extension_loaded( 'bcmath' );
	}

	public static function to_invoice_state( $status ) {
		switch ( (string) $status ) {
			case 'pending':     return 'created';
			case 'mempool':
			case 'unconfirmed':
			case 'partial':
			case 'underpaid':
			case 'locked':      return 'processing';
			case 'paid':        return 'settled';
			case 'expired':     return 'expired';
			case 'invalid':     return 'invalid';
			default:            return '';
		}
	}

	public static function is_address_like( $addr ) {
		$addr = trim( (string) $addr );
		return 1 === preg_match( '/^[1-9A-HJ-NP-Za-km-z]{95}$/', $addr )
			|| 1 === preg_match( '/^[1-9A-HJ-NP-Za-km-z]{106}$/', $addr );
	}

	const DEFAULT_CLAIM_WINDOW_SECS = 604800;

	public static function resolve_claim_window( $window_secs ) {
		if ( null === $window_secs ) {
			return self::DEFAULT_CLAIM_WINDOW_SECS;
		}
		$n = (int) $window_secs;
		return $n > 0 ? $n : 0;
	}

	public static function claim_window_from_days( $days ) {
		$d = (int) $days;
		return $d > 0 ? $d * 86400 : 0;
	}

	public static function claim_expires_at( $opened, $window_secs ) {
		$w = self::resolve_claim_window( $window_secs );
		return 0 === $w ? 0 : ( (int) $opened ) + $w;
	}

	public static function claim_expired( $status, $opened, $window_secs, $now ) {
		if ( 'requested' !== $status ) {
			return false;
		}
		$exp = self::claim_expires_at( $opened, $window_secs );
		if ( 0 === $exp ) {
			return false;
		}
		return (int) $now >= $exp;
	}

	public static function fmt( $xmr ) {
		$xmr = (float) $xmr;
		if ( ! is_finite( $xmr ) || $xmr <= 0 ) {
			return '0';
		}

		return self::pico_to_string( (int) round( $xmr * 1000000000000 ) );
	}

	public static function xmr_to_pico( $xmr ) {
		$xmr = (float) $xmr;
		if ( ! is_finite( $xmr ) || $xmr <= 0 ) {
			return 0;
		}
		return (int) round( $xmr * 1000000000000 );
	}

	/** Decimal XMR string to atomic units, with no floating-point conversion or rounding. */
	public static function xmr_to_pico_exact( $xmr ) {
		if ( ! is_string( $xmr ) || ! preg_match( '/^([0-9]+)(?:\.([0-9]{1,12}))?$/D', $xmr, $parts ) ) {
			throw new \InvalidArgumentException( 'XMR amount must be a decimal string with at most 12 fractional digits' );
		}
		$whole = gmp_mul( gmp_init( $parts[1], 10 ), '1000000000000' );
		$fraction = str_pad( isset( $parts[2] ) ? $parts[2] : '', 12, '0' );
		return gmp_strval( gmp_add( $whole, gmp_init( $fraction, 10 ) ) );
	}

	public static function pico_to_string( $pico ) {
		$p = gmp_init( (string) $pico, 10 );
		if ( gmp_cmp( $p, 0 ) <= 0 ) {
			return '0';
		}
		$denom = gmp_init( '1000000000000', 10 );
		$int   = gmp_strval( gmp_div_q( $p, $denom ) );
		$frac  = (int) gmp_strval( gmp_mod( $p, $denom ) );
		if ( 0 === $frac ) {
			return $int;
		}
		$fs = rtrim( str_pad( (string) $frac, self::XMR_DECIMALS, '0', STR_PAD_LEFT ), '0' );
		return $int . '.' . $fs;
	}

	public static function nonce_amount( $xmr, $digits = 9 ) {
		$digits = (int) $digits;
		if ( $digits < 1 || $digits > 12 ) {
			$digits = 9;
		}
		$base = self::xmr_to_pico( $xmr );
		if ( $base <= 0 ) {
			return '0';
		}
		$span  = ( 10 ** $digits ) - 1;
		$nonce = random_int( 1, $span );
		return self::pico_to_string( $base + $nonce );
	}

	public static function from_total( $total, $rate ) {
		$rate = (float) $rate;
		if ( $rate <= 0 ) {
			return '0';
		}
		return self::fmt( (float) $total / $rate );
	}

	public static function classify_payment( $expected_pico, $received_pico, $tolerance_pico, $min_conf, $confirmations, $in_pool, $locked ) {
		$exp = gmp_init( (string) $expected_pico, 10 );
		$rec = gmp_init( (string) $received_pico, 10 );
		$tol = gmp_init( (string) $tolerance_pico, 10 );
		if ( gmp_cmp( $tol, 0 ) < 0 ) { $tol = gmp_init( 0 ); }

		$max_tol = gmp_sub( $exp, gmp_init( 1 ) );
		if ( gmp_cmp( $exp, 0 ) <= 0 ) { $max_tol = gmp_init( 0 ); }
		if ( gmp_cmp( $tol, $max_tol ) > 0 ) { $tol = $max_tol; }
		$threshold = gmp_sub( $exp, $tol );

		$shortfall = gmp_cmp( $exp, $rec ) > 0 ? gmp_strval( gmp_sub( $exp, $rec ) ) : '0';

		if ( gmp_cmp( $rec, 0 ) <= 0 ) {
			return array( 'status' => 'pending', 'paid' => false, 'overpaid_pico' => '0', 'shortfall_pico' => gmp_strval( $exp ) );
		}
		if ( $locked ) {
			return array( 'status' => 'locked', 'paid' => false, 'overpaid_pico' => '0', 'shortfall_pico' => $shortfall );
		}
		if ( gmp_cmp( $rec, $threshold ) < 0 ) {
			return array( 'status' => 'underpaid', 'paid' => false, 'overpaid_pico' => '0', 'shortfall_pico' => $shortfall );
		}
		if ( (int) $confirmations < (int) $min_conf ) {
			return array( 'status' => $in_pool ? 'mempool' : 'unconfirmed', 'paid' => false, 'overpaid_pico' => '0', 'shortfall_pico' => '0' );
		}
		$overpaid = gmp_cmp( $rec, $exp ) > 0 ? gmp_strval( gmp_sub( $rec, $exp ) ) : '0';
		return array( 'status' => 'paid', 'paid' => true, 'overpaid_pico' => $overpaid, 'shortfall_pico' => '0' );
	}

	public static function verify_sig( $raw, $sig, $secret ) {
		if ( $secret === '' || $secret === null ) {
			return false;
		}
		if ( ! is_string( $sig ) || $sig === '' ) {
			return false;
		}
		$expected = 'sha256=' . hash_hmac( 'sha256', (string) $raw, (string) $secret );
		return hash_equals( $expected, $sig );
	}

	public static function event_fresh( $event_ts_ms, $now_s, $max_age_s = 86400 ) {
		if ( ! is_numeric( $event_ts_ms ) ) {
			return true;
		}
		return ( (float) $now_s - ( (float) $event_ts_ms / 1000.0 ) ) <= (float) $max_age_s;
	}

	public static function test_amount_allowed( $network, $tested_url, $agent_url, $address = '' ) {
		if ( ! in_array( $network, array( 'stagenet', 'testnet' ), true ) ) {
			return false;
		}

		if ( '' !== $address ) {
			$first           = $address[0];
			$is_test_address = in_array( $first, array( '5', '7', '9', 'A', 'B' ), true );
			if ( ! $is_test_address ) {
				return false;
			}
		}
		$tested = rtrim( trim( (string) $tested_url ), '/' );
		$agent  = rtrim( trim( (string) $agent_url ), '/' );
		return $tested !== '' && $tested === $agent;
	}

	public static function same_origin( $url, $home ) {
		$h = parse_url( (string) $url, PHP_URL_HOST );
		if ( empty( $h ) ) {
			return true;
		}
		$hh = parse_url( (string) $home, PHP_URL_HOST );
		return strtolower( $h ) === strtolower( (string) $hh );
	}

	private static function row_amt_pico( $row ) {
		$v = isset( $row['amount_atomic'] ) ? (string) $row['amount_atomic'] : '0';
		if ( '' === $v || ! preg_match( '/^-?\d+$/', $v ) ) { return gmp_init( 0 ); }
		$g = gmp_init( $v, 10 );
		return gmp_cmp( $g, 0 ) < 0 ? gmp_init( 0 ) : $g;
	}

	private static function more_creditable( $a, $b ) {
		$ak = ! empty( $a['commitment_ok'] ) && empty( $a['carrot'] );
		$bk = ! empty( $b['commitment_ok'] ) && empty( $b['carrot'] );
		if ( $ak !== $bk ) { return $ak ? $a : $b; }
		$ap = ! empty( $a['in_pool'] );
		$bp = ! empty( $b['in_pool'] );
		if ( $ap !== $bp ) { return $ap ? $b : $a; }
		$ac = ( isset( $a['confirmations'] ) && null !== $a['confirmations'] ) ? (int) $a['confirmations'] : -1;
		$bc = ( isset( $b['confirmations'] ) && null !== $b['confirmations'] ) ? (int) $b['confirmations'] : -1;
		if ( $ac !== $bc ) { return $ac > $bc ? $a : $b; }
		$al = ! empty( $a['locked'] );
		$bl = ! empty( $b['locked'] );
		if ( $al !== $bl ) { return $al ? $a : $b; }
		$cmp = gmp_cmp( self::row_amt_pico( $a ), self::row_amt_pico( $b ) );
		if ( 0 !== $cmp ) { return $cmp < 0 ? $a : $b; }
		return $a;
	}

	public static function dedup_outputs( $rows ) {
		if ( ! is_array( $rows ) ) { return array(); }
		$pos = array();
		$out = array();
		foreach ( $rows as $t ) {
			if ( ! is_array( $t ) ) { $out[] = $t; continue; }
			$k = ( isset( $t['out_key'] ) && '' !== (string) $t['out_key'] ) ? 'k:' . (string) $t['out_key']
				: ( ( isset( $t['txid'] ) && '' !== (string) $t['txid'] ) ? 't:' . (string) $t['txid'] : '' );
			if ( '' === $k ) { $out[] = $t; continue; }
			if ( ! isset( $pos[ $k ] ) ) { $pos[ $k ] = count( $out ); $out[] = $t; }
			else { $out[ $pos[ $k ] ] = self::more_creditable( $out[ $pos[ $k ] ], $t ); }
		}
		return $out;
	}

	public static function summarize_payments( $rows, $exp_pico, $tol_pico, $min_conf ) {
		$min_conf = max( 0, (int) $min_conf );
		$rows     = self::dedup_outputs( is_array( $rows ) ? $rows : array() );
		$confirmed = gmp_init( 0 );
		$pending   = gmp_init( 0 );
		$locked    = gmp_init( 0 );
		$min_confs = null;
		$txids     = array();
		foreach ( $rows as $t ) {

			if ( ! is_array( $t ) || empty( $t['commitment_ok'] ) ) { continue; }
			if ( ! empty( $t['carrot'] ) ) { continue; }
			$amt = self::row_amt_pico( $t );
			if ( isset( $t['txid'] ) && '' !== (string) $t['txid'] ) { $txids[] = (string) $t['txid']; }
			if ( ! empty( $t['locked'] ) ) { $locked = gmp_add( $locked, $amt ); continue; }

			if ( ! empty( $t['double_spend_seen'] ) ) { $pending = gmp_add( $pending, $amt ); continue; }
			$confs   = ( isset( $t['confirmations'] ) && null !== $t['confirmations'] ) ? (int) $t['confirmations'] : null;
			$in_pool = ! empty( $t['in_pool'] );
			if ( ! $in_pool && null !== $confs && $confs >= $min_conf ) {
				$confirmed = gmp_add( $confirmed, $amt );
				$min_confs = ( null === $min_confs ) ? $confs : min( $min_confs, $confs );
			} else {
				$pending = gmp_add( $pending, $amt );
			}
		}

		$exp = gmp_init( (string) $exp_pico, 10 );
		$tol = gmp_init( (string) $tol_pico, 10 );
		if ( gmp_cmp( $tol, 0 ) < 0 ) { $tol = gmp_init( 0 ); }
		$max_tol = gmp_cmp( $exp, 0 ) <= 0 ? gmp_init( 0 ) : gmp_sub( $exp, gmp_init( 1 ) );
		if ( gmp_cmp( $tol, $max_tol ) > 0 ) { $tol = $max_tol; }
		$threshold = gmp_sub( $exp, $tol );
		$seen      = gmp_add( gmp_add( $confirmed, $pending ), $locked );

		$base = array(
			'received_pico'  => gmp_strval( $confirmed ),
			'confirmed_pico' => gmp_strval( $confirmed ),
			'pending_pico'   => gmp_strval( $pending ),
			'locked_pico'    => gmp_strval( $locked ),
			'seen_pico'      => gmp_strval( $seen ),
			'confirmations'  => ( null === $min_confs ) ? 0 : (int) $min_confs,
			'txids'          => $txids,
			'overpaid_pico'  => '0',
			'shortfall_pico' => gmp_cmp( $threshold, $seen ) > 0 ? gmp_strval( gmp_sub( $threshold, $seen ) ) : '0',
		);

		if ( gmp_cmp( $exp, 0 ) <= 0 ) { return array_merge( $base, array( 'paid' => false, 'status' => 'invalid' ) ); }
		if ( gmp_cmp( $confirmed, $threshold ) >= 0 ) {
			$over = gmp_cmp( $confirmed, $exp ) > 0 ? gmp_strval( gmp_sub( $confirmed, $exp ) ) : '0';
			return array_merge( $base, array( 'paid' => true, 'status' => 'paid', 'overpaid_pico' => $over, 'shortfall_pico' => '0' ) );
		}
		if ( gmp_cmp( gmp_add( $locked, $confirmed ), $threshold ) >= 0 ) { return array_merge( $base, array( 'paid' => false, 'status' => 'locked' ) ); }
		if ( gmp_cmp( gmp_add( $confirmed, $pending ), $threshold ) >= 0 ) { return array_merge( $base, array( 'paid' => false, 'status' => 'mempool' ) ); }
		if ( gmp_cmp( $confirmed, 0 ) > 0 || gmp_cmp( $pending, 0 ) > 0 ) { return array_merge( $base, array( 'paid' => false, 'status' => 'partial' ) ); }
		return array_merge( $base, array( 'paid' => false, 'status' => 'pending' ) );
	}
}
