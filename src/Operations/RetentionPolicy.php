<?php
/**
 * Closed Free retention policy.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

final class RetentionPolicy {
	public const EVENT_OPTION   = 'checkout_firewall_event_retention_days';
	public const HISTORY_OPTION = 'checkout_firewall_block_history_retention_days';
	public const HINT_OPTION    = 'checkout_firewall_block_hint_retention_days';

	public static function event_seconds(): int {
		return self::days( self::EVENT_OPTION, array( 1, 3, 7 ), 7 ) * DAY_IN_SECONDS;
	}

	public static function history_seconds(): int {
		return self::days( self::HISTORY_OPTION, array( 1, 3, 7 ), 7 ) * DAY_IN_SECONDS;
	}

	public static function hint_seconds(): int {
		return self::days( self::HINT_OPTION, array( 7, 30, 90 ), 90 ) * DAY_IN_SECONDS;
	}

	/**
	 * Validate and persist one closed retention choice.
	 *
	 * @param list<int> $allowed Allowed values.
	 */
	public static function save( string $option, int $value, array $allowed ): bool {
		if ( ! self::accepts( $value, $allowed ) ) {
			return false;
		}
		self::write( $option, $value );
		return true;
	}

	/**
	 * Determine whether a value is in the closed set.
	 *
	 * @param list<int> $allowed Allowed values.
	 */
	public static function accepts( int $value, array $allowed ): bool {
		return in_array( $value, $allowed, true );
	}

	/**
	 * Read one privacy-preserving retained-day value.
	 *
	 * @param list<int> $allowed Allowed values.
	 */
	private static function days( string $option, array $allowed, int $fallback ): int {
		$value = (int) get_option( $option, $fallback );
		return in_array( $value, $allowed, true ) ? $value : $fallback;
	}

	private static function write( string $option, int $value ): void {
		if ( false === get_option( $option, false ) ) {
			add_option( $option, $value, '', false );
			return;
		}
		update_option( $option, $value, false );
	}
}
