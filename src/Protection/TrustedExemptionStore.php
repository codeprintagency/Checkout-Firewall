<?php
/**
 * Bounded local trusted-exemption persistence.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Operations\IdentityMasker;
use Codeprint\CheckoutFirewall\Security\KeyStore;

final class TrustedExemptionStore {
	public const OPTION    = 'checkout_firewall_trusted_exemptions';
	public const MAX_ROWS  = 100;
	public const REASONS   = array( 'office_network', 'wholesale_customer', 'vip_customer', 'testing' );
	public const DURATIONS = array( 86400, 604800, 2592000 );
	private KeyStore $keys;
	/**
	 * Clock used for bounded expiration handling.
	 *
	 * @var \Closure():int
	 */
	private \Closure $clock;
	/**
	 * Random-byte source used for row identifiers.
	 *
	 * @var \Closure(int):string
	 */
	private \Closure $random;

	public function __construct( ?KeyStore $keys = null, ?callable $clock = null, ?callable $random = null ) {
		$this->keys   = $keys ?? new KeyStore();
		$this->clock  = \Closure::fromCallable( $clock ?? 'time' );
		$this->random = \Closure::fromCallable( $random ?? 'random_bytes' );
	}

	public function register(): void {
		add_action( 'deleted_user', array( $this, 'deleted_user' ), 10, 1 );
	}

	public function deleted_user( int $user_id ): void {
		try {
			$this->remove_user( $user_id );
		} catch ( \Throwable $exception ) {
			unset( $exception );
		}
	}

	/**
	 * Return active, validated exemption rows.
	 *
	 * @return list<array<string,mixed>>
	 */
	public function active(): array {
		return $this->normalize( get_option( self::OPTION, false ), ( $this->clock )() )['rows'];
	}

	/**
	 * Create an exact-address or narrowly-scoped network exemption.
	 *
	 * @return array<string,mixed>
	 * @throws \InvalidArgumentException When the address, network, or policy is invalid.
	 */
	public function create_ip( string $value, string $reason, ?int $seconds ): array {
		$this->validate_common( $reason, $seconds );
		$value = strtolower( trim( $value ) );
		if ( false !== strpos( $value, '/' ) ) {
			$parts  = explode( '/', $value, 2 );
			$packed = inet_pton( $parts[0] );
			$prefix = ctype_digit( $parts[1] ) ? (int) $parts[1] : -1;
			$bits   = false === $packed ? 0 : 8 * strlen( $packed );
			$valid  = ( 32 === $bits && $prefix >= 24 && $prefix <= 32 ) || ( 128 === $bits && $prefix >= 64 && $prefix <= 128 );
			if ( ! $valid ) {
				throw new \InvalidArgumentException( 'Trusted network is invalid or too broad.' );
			}
			$network   = self::masked_network( $packed, $prefix );
			$canonical = inet_ntop( $network );
			if ( false === $canonical ) {
				throw new \InvalidArgumentException( 'Trusted network is invalid.' );
			}
			return $this->append(
				array(
					'subject_type' => 'network',
					'network'      => strtolower( $canonical ),
					'prefix'       => $prefix,
					'hint'         => strtolower( $canonical ) . '/' . $prefix,
				),
				$reason,
				$seconds
			);
		}
		$packed = inet_pton( $value );
		if ( false === $packed ) {
			throw new \InvalidArgumentException( 'Trusted IP is invalid.' );
		}
		$canonical = inet_ntop( $packed );
		if ( false === $canonical ) {
			throw new \InvalidArgumentException( 'Trusted IP is invalid.' );
		}
		$anchor = $this->keys->active_key( IdentifierType::IP, strtolower( $canonical ) );
		return $this->append(
			array(
				'subject_type'           => 'ip',
				'active_key_version'     => $anchor['active_key_version'],
				'active_key_fingerprint' => bin2hex( $anchor['active_key_fingerprint'] ),
				'active_key'             => bin2hex( $anchor['active_key'] ),
				'hint'                   => IdentityMasker::ip( strtolower( $canonical ) ),
			),
			$reason,
			$seconds
		);
	}

	/**
	 * Create an exemption for an existing WordPress user.
	 *
	 * @return array<string,mixed>
	 * @throws \InvalidArgumentException When the user or policy is invalid.
	 */
	public function create_user( int $user_id, string $reason, ?int $seconds ): array {
		$this->validate_common( $reason, $seconds );
		if ( $user_id < 1 || ! function_exists( 'get_userdata' ) || false === get_userdata( $user_id ) ) {
			throw new \InvalidArgumentException( 'Trusted user is invalid.' );
		}
		return $this->append(
			array(
				'subject_type' => 'user',
				'user_id'      => $user_id,
				'hint'         => '',
			),
			$reason,
			$seconds
		);
	}

	public function remove( string $id ): bool {
		if ( 1 !== preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			return false;
		}
		for ( $attempt = 0; $attempt < 3; ++$attempt ) {
			$raw             = get_option( self::OPTION, false );
			$current         = $this->normalize( $raw, ( $this->clock )() );
			$before          = count( $current['rows'] );
			$current['rows'] = array_values( array_filter( $current['rows'], static fn( array $row ): bool => ! hash_equals( $row['id'], $id ) ) );
			if ( count( $current['rows'] ) === $before ) {
				return false;
			}
			if ( $this->store( $raw, $current ) ) {
				return true;
			}
		}
		throw new \RuntimeException( 'Trusted exemption could not be removed.' );
	}

	public function remove_user( int $user_id ): bool {
		if ( $user_id < 1 ) {
			return false;
		}
		for ( $attempt = 0; $attempt < 3; ++$attempt ) {
			$raw             = get_option( self::OPTION, false );
			$current         = $this->normalize( $raw, ( $this->clock )() );
			$before          = count( $current['rows'] );
			$current['rows'] = array_values( array_filter( $current['rows'], static fn( array $row ): bool => 'user' !== $row['subject_type'] || $user_id !== $row['user_id'] ) );
			if ( count( $current['rows'] ) === $before ) {
				return false;
			}
			if ( $this->store( $raw, $current ) ) {
				return true;
			}
		}
		throw new \RuntimeException( 'Trusted user exemption could not be removed.' );
	}

	/**
	 * Append one validated subject to the bounded store.
	 *
	 * @param array<string,mixed> $subject Subject fields.
	 * @return array<string,mixed>
	 * @throws \RuntimeException When the store is full or cannot be saved.
	 */
	private function append( array $subject, string $reason, ?int $seconds ): array {
		$now    = ( $this->clock )();
		$random = ( $this->random )( 16 );
		if ( 16 !== strlen( $random ) ) {
			throw new \RuntimeException( 'Trusted exemption random source failed.' );
		}
		$row = array_merge(
			array(
				'id'             => bin2hex( $random ),
				'status'         => 'active',
				'reason'         => $reason,
				'created_at_gmt' => gmdate( 'Y-m-d H:i:s', $now ),
				'expires_at_gmt' => null === $seconds ? '9999-12-31 23:59:59' : gmdate( 'Y-m-d H:i:s', $now + $seconds ),
			),
			$subject
		);
		for ( $attempt = 0; $attempt < 3; ++$attempt ) {
			$raw     = get_option( self::OPTION, false );
			$current = $this->normalize( $raw, $now );
			if ( count( $current['rows'] ) >= self::MAX_ROWS ) {
				throw new \RuntimeException( 'Trusted exemption limit reached.' );
			}
			$current['rows'][] = $row;
			if ( strlen( maybe_serialize( $current ) ) > 65536 ) {
				throw new \RuntimeException( 'Trusted exemption store exceeds its bound.' );
			}
			if ( $this->store( $raw, $current ) ) {
				return $row;
			}
		}
		throw new \RuntimeException( 'Trusted exemption could not be saved.' );
	}

	private function validate_common( string $reason, ?int $seconds ): void {
		if ( ! in_array( $reason, self::REASONS, true ) || ( null !== $seconds && ! in_array( $seconds, self::DURATIONS, true ) ) ) {
			throw new \InvalidArgumentException( 'Trusted exemption policy is invalid.' );
		}
	}

	/**
	 * Normalize and prune persisted exemption state.
	 *
	 * @return array{format:int,revision:int,rows:list<array<string,mixed>>}
	 */
	private function normalize( mixed $value, int $now ): array {
		$empty = array(
			'format'   => 1,
			'revision' => 0,
			'rows'     => array(),
		);
		if ( ! is_array( $value ) || array( 'format', 'revision', 'rows' ) !== array_keys( $value ) || 1 !== $value['format'] || ! is_int( $value['revision'] ) || 0 > $value['revision'] || ! is_array( $value['rows'] ) || 65536 < strlen( maybe_serialize( $value ) ) ) {
			return $empty;
		}
		$rows = array();
		foreach ( array_slice( $value['rows'], -self::MAX_ROWS ) as $row ) {
			if ( is_array( $row ) && $this->valid_row( $row, $now ) ) {
				$rows[] = $row;
			}
		}
		return array(
			'format'   => 1,
			'revision' => $value['revision'],
			'rows'     => $rows,
		);
	}

	/**
	 * Validate one persisted exemption row.
	 *
	 * @param array<string,mixed> $row Exemption row.
	 */
	private function valid_row( array $row, int $now ): bool {
		$expiry = isset( $row['expires_at_gmt'] ) && is_string( $row['expires_at_gmt'] ) ? strtotime( $row['expires_at_gmt'] . ' UTC' ) : false;
		$common = array( 'id', 'status', 'reason', 'created_at_gmt', 'expires_at_gmt', 'subject_type' );
		if ( 1 !== preg_match( '/^[a-f0-9]{32}$/D', (string) ( $row['id'] ?? '' ) ) || 'active' !== ( $row['status'] ?? null ) || ! in_array( $row['reason'] ?? null, self::REASONS, true ) || ! self::valid_date( $row['created_at_gmt'] ?? null ) || false === $expiry || $expiry <= $now || ! in_array( $row['subject_type'] ?? null, array( 'ip', 'network', 'user' ), true ) ) {
			return false;
		}
		if ( 'user' === $row['subject_type'] ) {
			return array_merge( $common, array( 'user_id', 'hint' ) ) === array_keys( $row ) && is_int( $row['user_id'] ) && 0 < $row['user_id'] && '' === $row['hint'];
		}
		if ( 'ip' === $row['subject_type'] ) {
			return array_merge( $common, array( 'active_key_version', 'active_key_fingerprint', 'active_key', 'hint' ) ) === array_keys( $row )
				&& is_int( $row['active_key_version'] ) && 0 < $row['active_key_version']
				&& 1 === preg_match( '/^[a-f0-9]{16}$/D', (string) $row['active_key_fingerprint'] )
				&& 1 === preg_match( '/^[a-f0-9]{64}$/D', (string) $row['active_key'] )
				&& is_string( $row['hint'] ) && 191 >= strlen( $row['hint'] );
		}
		if ( array_merge( $common, array( 'network', 'prefix', 'hint' ) ) !== array_keys( $row ) || ! is_string( $row['network'] ) || ! is_int( $row['prefix'] ) || ! is_string( $row['hint'] ) ) {
			return false;
		}
		$packed = inet_pton( $row['network'] );
		$bits   = false === $packed ? 0 : 8 * strlen( $packed );
		$valid  = ( 32 === $bits && 24 <= $row['prefix'] && 32 >= $row['prefix'] ) || ( 128 === $bits && 64 <= $row['prefix'] && 128 >= $row['prefix'] );
		if ( ! $valid || false === $packed ) {
			return false;
		}
		$canonical = inet_ntop( self::masked_network( $packed, $row['prefix'] ) );
		return false !== $canonical && strtolower( $canonical ) === $row['network'] && $row['hint'] === $row['network'] . '/' . $row['prefix'];
	}

	/**
	 * Store the next revision with compare-and-swap where available.
	 *
	 * @param array{format:int,revision:int,rows:list<array<string,mixed>>} $next Next state.
	 */
	private function store( mixed $raw, array $next ): bool {
		++$next['revision'];
		if ( false === $raw ) {
			return add_option( self::OPTION, $next, '', false );
		}
		global $wpdb;
		if ( is_object( $wpdb ) && method_exists( $wpdb, 'query' ) && method_exists( $wpdb, 'prepare' ) ) {
			$result = $wpdb->query( $wpdb->prepare( "UPDATE `{$wpdb->options}` SET option_value=%s WHERE option_name=%s AND option_value=%s", maybe_serialize( $next ), self::OPTION, maybe_serialize( $raw ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			wp_cache_delete( self::OPTION, 'options' );
			return 1 === $result;
		}
		return update_option( self::OPTION, $next, false );
	}

	private static function masked_network( string $packed, int $prefix ): string {
		$bytes = strlen( $packed );
		$out   = '';
		for ( $index = 0; $index < $bytes; ++$index ) {
			$remaining = $prefix - ( $index * 8 );
			$mask      = $remaining >= 8 ? 255 : ( $remaining <= 0 ? 0 : ( 256 - ( 1 << ( 8 - $remaining ) ) ) );
			$out      .= chr( ord( $packed[ $index ] ) & $mask );
		}
		return $out;
	}

	private static function valid_date( mixed $value ): bool {
		return is_string( $value ) && 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $value ) && false !== strtotime( $value . ' UTC' );
	}
}
