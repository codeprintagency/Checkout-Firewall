<?php
/**
 * Fail-safe client IP resolution.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

final class ClientIpResolver {
	public const MODE_OPTION       = 'cwf_proxy_mode';
	public const HEADER_OPTION     = 'cwf_proxy_header';
	public const CIDRS_OPTION      = 'cwf_trusted_proxy_cidrs';
	public const MODE_AUTOMATIC    = 'automatic';
	public const MODE_MANUAL       = 'manual';
	private const MAX_CHAIN        = 16;
	private const MAX_BYTES        = 2048;
	private const CLOUDFLARE_CIDRS = array(
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'108.162.192.0/18',
		'131.0.72.0/22',
		'141.101.64.0/18',
		'162.158.0.0/15',
		'172.64.0.0/13',
		'173.245.48.0/20',
		'188.114.96.0/20',
		'190.93.240.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * Validate and persist one closed proxy policy.
	 *
	 * @param list<string> $cidrs Manual trusted proxy ranges.
	 * @throws \InvalidArgumentException For a policy outside the closed set.
	 */
	public function save_policy( string $mode, string $header, array $cidrs ): void {
		$policy = $this->validate_policy( $mode, $header, $cidrs );
		self::write( self::MODE_OPTION, $policy['mode'] );
		self::write( self::HEADER_OPTION, $policy['header'] );
		self::write( self::CIDRS_OPTION, $policy['cidrs'] );
	}

	/**
	 * Validate and canonicalize a policy without changing stored state.
	 *
	 * @param list<string> $cidrs Manual trusted proxy ranges.
	 * @return array{mode:string,header:string,cidrs:list<string>}
	 * @throws \InvalidArgumentException For a policy outside the closed set.
	 */
	public function validate_policy( string $mode, string $header, array $cidrs ): array {
		$mode = self::normalize_mode( $mode );
		if ( null === $mode ) {
			throw new \InvalidArgumentException( 'Invalid proxy mode.' );
		}
		if ( ! in_array( $header, array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ), true ) ) {
			throw new \InvalidArgumentException( 'Invalid proxy header.' );
		}
		$cidrs = array_values( array_unique( array_map( 'trim', $cidrs ) ) );
		if ( self::MODE_MANUAL === $mode && ( count( $cidrs ) < 1 || count( $cidrs ) > 64 || ! $this->valid_cidrs( $cidrs ) ) ) {
			throw new \InvalidArgumentException( 'Invalid trusted proxy ranges.' );
		}
		if ( self::MODE_MANUAL !== $mode ) {
			$cidrs = array();
		}
		return array(
			'mode'   => $mode,
			'header' => $header,
			'cidrs'  => $cidrs,
		);
	}

	public function configuration_status(): string {
		$mode = $this->configured_mode();
		if ( 'invalid' === $mode ) {
			return 'invalid';
		}
		if ( self::MODE_MANUAL !== $mode ) {
			return 'healthy';
		}
		$header = get_option( self::HEADER_OPTION, 'HTTP_X_FORWARDED_FOR' );
		$cidrs  = get_option( self::CIDRS_OPTION, array() );
		return in_array( $header, array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ), true ) && is_array( $cidrs ) && count( $cidrs ) <= 64 && $this->valid_cidrs( $cidrs ) ? 'healthy' : 'invalid';
	}

	/**
	 * Return the normalized runtime mode while accepting pre-automatic values.
	 */
	public function configured_mode(): string {
		$stored = get_option( self::MODE_OPTION, self::MODE_AUTOMATIC );
		$mode   = is_string( $stored ) ? self::normalize_mode( $stored ) : null;
		return $mode ?? 'invalid';
	}

	/**
	 * Describe the current request's verified edge path without trusting headers alone.
	 *
	 * @param array<string,mixed>|null $server Server values.
	 */
	public function edge_status( ?array $server = null ): string {
		$server = $server ?? $_SERVER;
		$remote = $this->address( $server['REMOTE_ADDR'] ?? null );
		if ( null === $remote ) {
			return 'unknown';
		}
		if ( ! $this->in_any_cidr( $remote, self::CLOUDFLARE_CIDRS ) ) {
			return 'direct';
		}
		return null === $this->address( $server['HTTP_CF_CONNECTING_IP'] ?? null ) ? 'cloudflare_header_missing' : 'cloudflare';
	}

	/**
	 * Resolve from a supplied server map or the current request.
	 *
	 * @param array<string,mixed>|null $server Server values.
	 */
	public function resolve( ?array $server = null ): ?string {
		$server = $server ?? $_SERVER;
		$remote = $this->address( $server['REMOTE_ADDR'] ?? null );
		if ( null === $remote ) {
			return null;
		}

		$mode = $this->configured_mode();
		if ( self::MODE_AUTOMATIC === $mode ) {
			return 'cloudflare' === $this->edge_status( $server ) ? $this->address( $server['HTTP_CF_CONNECTING_IP'] ?? null ) ?? $remote : $remote;
		}
		if ( self::MODE_MANUAL !== $mode ) {
			return $remote;
		}

		$cidrs = get_option( self::CIDRS_OPTION, array() );
		if ( ! is_array( $cidrs ) || count( $cidrs ) > 64 || ! $this->valid_cidrs( $cidrs ) || ! $this->in_any_cidr( $remote, $cidrs ) ) {
			return $remote;
		}
		$header = get_option( self::HEADER_OPTION, 'HTTP_X_FORWARDED_FOR' );
		if ( ! in_array( $header, array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ), true ) ) {
			return $remote;
		}
		$value = $server[ $header ] ?? null;
		if ( ! is_string( $value ) || '' === $value || strlen( $value ) > self::MAX_BYTES ) {
			return $remote;
		}
		if ( 'HTTP_X_REAL_IP' === $header ) {
			return $this->address( $value ) ?? $remote;
		}

		$parts = array_map( 'trim', explode( ',', $value ) );
		if ( array() === $parts || count( $parts ) > self::MAX_CHAIN ) {
			return $remote;
		}
		$addresses = array();
		foreach ( $parts as $part ) {
			$address = $this->address( $part );
			if ( null === $address ) {
				return $remote;
			}
			$addresses[] = $address;
		}
		$addresses[] = $remote;
		for ( $index = count( $addresses ) - 1; $index >= 0; --$index ) {
			if ( ! $this->in_any_cidr( $addresses[ $index ], $cidrs ) ) {
				return $addresses[ $index ];
			}
		}
		return $remote;
	}

	/**
	 * Normalize the retired explicit Direct/Cloudflare choices into automatic mode.
	 */
	private static function normalize_mode( string $mode ): ?string {
		if ( in_array( $mode, array( self::MODE_AUTOMATIC, 'direct', 'cloudflare' ), true ) ) {
			return self::MODE_AUTOMATIC;
		}
		return self::MODE_MANUAL === $mode ? self::MODE_MANUAL : null;
	}

	/**
	 * Parse and canonicalize one address.
	 *
	 * @param mixed $value Candidate address.
	 */
	private function address( $value ): ?string {
		if ( ! is_string( $value ) || '' === $value || trim( $value ) !== $value || false !== strpbrk( $value, "[]%\r\n\t " ) ) {
			return null;
		}
		$packed = inet_pton( $value );
		if ( false === $packed ) {
			return null;
		}
		$canonical = inet_ntop( $packed );
		return false === $canonical ? null : strtolower( $canonical );
	}

	/**
	 * Validate a bounded CIDR list.
	 *
	 * @param array<mixed> $cidrs Candidate CIDRs.
	 */
	private function valid_cidrs( array $cidrs ): bool {
		foreach ( $cidrs as $cidr ) {
			if ( ! is_string( $cidr ) || null === $this->parse_cidr( $cidr ) ) {
				return false;
			}
		}
		return array() !== $cidrs;
	}

	/**
	 * Test an address against a CIDR list.
	 *
	 * @param array<mixed> $cidrs Candidate CIDRs.
	 */
	private function in_any_cidr( string $address, array $cidrs ): bool {
		$packed = inet_pton( $address );
		if ( false === $packed ) {
			return false;
		}
		foreach ( $cidrs as $cidr ) {
			$parsed = is_string( $cidr ) ? $this->parse_cidr( $cidr ) : null;
			if ( null === $parsed || strlen( $packed ) !== strlen( $parsed[0] ) ) {
				continue;
			}
			$full = intdiv( $parsed[1], 8 );
			$bits = $parsed[1] % 8;
			if ( substr( $packed, 0, $full ) !== substr( $parsed[0], 0, $full ) ) {
				continue;
			}
			if ( 0 === $bits || ( ord( $packed[ $full ] ) & ( 0xff << ( 8 - $bits ) ) ) === ( ord( $parsed[0][ $full ] ) & ( 0xff << ( 8 - $bits ) ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Parse one CIDR into packed bytes and its prefix length.
	 *
	 * @return array{string,int}|null
	 */
	private function parse_cidr( string $cidr ): ?array {
		$parts = explode( '/', $cidr );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[1] ) ) {
			return null;
		}
		$packed = inet_pton( $parts[0] );
		$bits   = (int) $parts[1];
		if ( false === $packed || $bits < 0 || $bits > strlen( $packed ) * 8 ) {
			return null;
		}
		return array( $packed, $bits );
	}

	/**
	 * Persist one non-autoloaded proxy option.
	 *
	 * @param mixed $value Option value.
	 */
	private static function write( string $option, $value ): void {
		if ( false === get_option( $option, false ) ) {
			add_option( $option, $value, '', false );
			return;
		}
		update_option( $option, $value, false );
	}
}
