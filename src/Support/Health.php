<?php
/**
 * Bounded machine-readable health state.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Support;

final class Health {
	public const OPTION = 'cwf_health_state';
	private const LIMIT = 20;

	public static function record( string $component, string $code ): void {
		$state = self::read();
		unset( $state[ $component ] );
		$state[ $component ] = array(
			'code'           => sanitize_key( $code ),
			'updated_at_gmt' => gmdate( 'Y-m-d H:i:s' ),
		);

		self::write( $state );
	}

	public static function clear( string $component ): void {
		$state = self::read();
		if ( ! array_key_exists( $component, $state ) ) {
			return;
		}

		unset( $state[ $component ] );
		self::write( $state );
	}

	public static function timestamp( string $key ): int {
		$state = self::read();
		return isset( $state[ $key ] ) && is_int( $state[ $key ] ) ? $state[ $key ] : 0;
	}

	public static function set_timestamp( string $key, int $timestamp ): void {
		$state = self::read();
		unset( $state[ $key ] );
		$state[ $key ] = max( 0, $timestamp );
		self::write( $state );
	}

	/**
	 * Read bounded health state.
	 *
	 * @return array<string, mixed>
	 */
	private static function read(): array {
		$state = get_option( self::OPTION, array() );
		return is_array( $state ) ? array_slice( $state, -self::LIMIT, null, true ) : array();
	}

	/**
	 * Persist bounded health state without autoloading it.
	 *
	 * @param array<string, mixed> $state Bounded health state.
	 */
	private static function write( array $state ): void {
		$state = array_slice( $state, -self::LIMIT, null, true );
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, $state, '', false );
			return;
		}

		update_option( self::OPTION, $state, false );
	}
}
