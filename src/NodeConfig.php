<?php

namespace XmrPay;

use InvalidArgumentException;

/** Normalize legacy node URLs and structured authenticated node records. */
class NodeConfig {

	/**
	 * @param mixed $value A URL string, delimited URL list, JSON array, or PHP array.
	 * @return array<int,array<string,mixed>>
	 */
	public static function normalizeList( $value ) {
		$rows = self::inputRows( $value );
		$out  = array();

		foreach ( $rows as $row ) {
			$out[] = self::normalizeRow( $row );
		}

		if ( ! $out ) {
			throw new InvalidArgumentException( 'empty-node-list' );
		}

		return $out;
	}

	/** Return node metadata that is safe to expose in status and diagnostics. */
	public static function publicList( $nodes ) {
		$out = array();
		foreach ( (array) $nodes as $node ) {
			$out[] = array(
				'url'                 => isset( $node['url'] ) ? self::publicUrl( $node['url'] ) : '',
				'auth'                => isset( $node['auth'] ) ? (string) $node['auth'] : 'none',
				'allow_insecure_http' => ! empty( $node['allow_insecure_http'] ),
			);
		}
		return $out;
	}

	/** Strip query and fragment data from a normalized URL before public display. */
	public static function publicUrl( $url ) {
		$parts = parse_url( (string) $url );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		$host = false !== strpos( $parts['host'], ':' ) ? '[' . $parts['host'] . ']' : $parts['host'];
		$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
		$path = isset( $parts['path'] ) ? rtrim( $parts['path'], '/' ) : '';
		return strtolower( $parts['scheme'] ) . '://' . $host . $port . $path;
	}

	private static function inputRows( $value ) {
		if ( is_string( $value ) ) {
			$trimmed = trim( $value );
			if ( '' === $trimmed ) {
				throw new InvalidArgumentException( 'empty-node-list' );
			}
			if ( '[' === $trimmed[0] || '{' === $trimmed[0] ) {
				$decoded = json_decode( $trimmed, true );
				if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $decoded ) ) {
					throw new InvalidArgumentException( 'invalid-json' );
				}
				$value = $decoded;
			} else {
				return preg_split( '/[\r\n,]+/', $trimmed, -1, PREG_SPLIT_NO_EMPTY );
			}
		}

		if ( ! is_array( $value ) ) {
			throw new InvalidArgumentException( 'invalid-node-list' );
		}

		if ( self::isNodeRow( $value ) ) {
			return array( $value );
		}

		return array_values( $value );
	}

	private static function isNodeRow( $value ) {
		return array_key_exists( 'url', $value )
			|| array_key_exists( 'auth', $value )
			|| array_key_exists( 'username', $value )
			|| array_key_exists( 'password', $value );
	}

	private static function normalizeRow( $row ) {
		if ( is_string( $row ) ) {
			$row = array( 'url' => $row, 'auth' => 'none' );
		}
		if ( ! is_array( $row ) || ! self::isNodeRow( $row ) ) {
			throw new InvalidArgumentException( 'invalid-node' );
		}

		$url   = isset( $row['url'] ) ? rtrim( trim( (string) $row['url'] ), '/' ) : '';
		$parts = parse_url( $url );
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			throw new InvalidArgumentException( 'embedded-credentials' );
		}
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) || preg_match( '/\s/', $url ) ) {
			throw new InvalidArgumentException( 'invalid-url' );
		}

		$scheme = strtolower( (string) $parts['scheme'] );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			throw new InvalidArgumentException( 'invalid-scheme' );
		}
		if ( isset( $parts['query'] ) || isset( $parts['fragment'] ) ) {
			throw new InvalidArgumentException( 'invalid-url' );
		}

		// parse_url() tolerates hosts no HTTP client will resolve: percent-encoding (which
		// some URL parsers re-decode into userinfo — the classic parse_url/client split) and
		// a bare ':' from unbracketed IPv6. The JS twin's WHATWG parser rejects both.
		$host = (string) $parts['host'];
		if ( false !== strpos( $host, '%' ) ) {
			throw new InvalidArgumentException( 'invalid-url' );
		}
		if ( false !== strpos( $host, ':' ) && ( '[' !== $host[0] || ']' !== substr( $host, -1 ) ) ) {
			throw new InvalidArgumentException( 'invalid-url' );
		}

		$auth = isset( $row['auth'] ) ? strtolower( trim( (string) $row['auth'] ) ) : 'none';
		if ( '' === $auth ) {
			$auth = 'none';
		}
		if ( ! in_array( $auth, array( 'none', 'basic', 'digest' ), true ) ) {
			throw new InvalidArgumentException( 'invalid-auth' );
		}

		$username = isset( $row['username'] ) ? (string) $row['username'] : '';
		$password = isset( $row['password'] ) ? (string) $row['password'] : '';
		$allow    = self::toBool( isset( $row['allow_insecure_http'] ) ? $row['allow_insecure_http'] : false );
		if ( 'none' === $auth ) {
			$username = '';
			$password = '';
		} elseif ( '' === $username || '' === $password ) {
			throw new InvalidArgumentException( 'missing-credentials' );
		}
		if ( 'none' !== $auth && false !== strpos( $username, ':' ) ) {
			throw new InvalidArgumentException( 'invalid-username' );
		}

		if ( 'none' !== $auth && 'http' === $scheme && ! $allow ) {
			throw new InvalidArgumentException( 'insecure-http-auth' );
		}

		return array(
			'url'                 => $url,
			'auth'                => $auth,
			'username'            => $username,
			'password'            => $password,
			'allow_insecure_http' => $allow,
		);
	}

	private static function toBool( $value ) {
		if ( is_bool( $value ) ) {
			return $value;
		}
		return in_array( strtolower( trim( (string) $value ) ), array( '1', 'true', 'yes', 'on' ), true );
	}
}
