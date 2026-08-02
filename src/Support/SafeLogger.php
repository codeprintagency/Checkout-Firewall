<?php
/**
 * Rate-limited non-sensitive logging.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Support;

final class SafeLogger {
	private const RATE_LIMIT_SECONDS = 300;

	public static function exception( string $code, \Throwable $exception ): void {
		self::write( $code, get_class( $exception ) );
	}

	public static function error( string $code ): void {
		self::write( $code, 'operational_error' );
	}

	private static function write( string $code, string $category ): void {
		try {
			$code      = sanitize_key( $code );
			$rate_key  = 'log_' . substr( hash( 'sha256', $code ), 0, 12 );
			$last_time = Health::timestamp( $rate_key );

			if ( time() - $last_time < self::RATE_LIMIT_SECONDS ) {
				return;
			}

			Health::set_timestamp( $rate_key, time() );
			$message = sprintf( 'Checkout Firewall: %s (%s).', $code, sanitize_key( $category ) );

			if ( function_exists( 'wc_get_logger' ) ) {
				wc_get_logger()->error( $message, array( 'source' => 'checkout-firewall' ) );
				return;
			}

			if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
				error_log( $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			}
		} catch ( \Throwable $logging_exception ) {
			if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
				error_log( 'Checkout Firewall: logging_failed.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			}
		}
	}
}
