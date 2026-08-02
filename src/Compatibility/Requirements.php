<?php
/**
 * Runtime and activation requirements.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Compatibility;

final class Requirements {
	public const PHP_MINIMUM         = '8.0';
	public const WORDPRESS_MINIMUM   = '6.8';
	public const WOOCOMMERCE_MINIMUM = '10.7.0';

	public const PHP_UNSUPPORTED         = 'php_unsupported';
	public const WORDPRESS_UNSUPPORTED   = 'wordpress_unsupported';
	public const WOOCOMMERCE_MISSING     = 'woocommerce_missing';
	public const WOOCOMMERCE_UNSUPPORTED = 'woocommerce_unsupported';
	public const MULTISITE_UNSUPPORTED   = 'multisite_unsupported';
	public const INNODB_UNAVAILABLE      = 'innodb_unavailable';
	public const RANDOMNESS_UNAVAILABLE  = 'randomness_unavailable';

	public static function runtime_failure(): ?string {
		global $wp_version;

		return self::evaluate(
			PHP_VERSION,
			is_string( $wp_version ) ? $wp_version : '',
			defined( 'WC_VERSION' ) ? (string) WC_VERSION : null,
			is_multisite()
		);
	}

	public static function evaluate( string $php_version, string $wordpress_version, ?string $woocommerce_version, bool $multisite ): ?string {

		if ( version_compare( $php_version, self::PHP_MINIMUM, '<' ) ) {
			return self::PHP_UNSUPPORTED;
		}

		if ( version_compare( $wordpress_version, self::WORDPRESS_MINIMUM, '<' ) ) {
			return self::WORDPRESS_UNSUPPORTED;
		}

		if ( $multisite ) {
			return self::MULTISITE_UNSUPPORTED;
		}

		if ( null === $woocommerce_version ) {
			return self::WOOCOMMERCE_MISSING;
		}

		if ( version_compare( $woocommerce_version, self::WOOCOMMERCE_MINIMUM, '<' ) ) {
			return self::WOOCOMMERCE_UNSUPPORTED;
		}

		return null;
	}

	public static function activation_failure(): ?string {
		$failure = self::runtime_failure();
		if ( null !== $failure ) {
			return $failure;
		}

		if ( ! self::has_innodb() ) {
			return self::INNODB_UNAVAILABLE;
		}

		try {
			$probe = random_bytes( 1 );
			if ( 1 !== strlen( $probe ) ) {
				return self::RANDOMNESS_UNAVAILABLE;
			}
		} catch ( \Throwable $exception ) {
			return self::RANDOMNESS_UNAVAILABLE;
		}

		return null;
	}

	private static function has_innodb(): bool {
		global $wpdb;

		$rows = $wpdb->get_results( 'SHOW ENGINES', ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( ! is_array( $rows ) ) {
			return false;
		}

		foreach ( $rows as $row ) {
			$engine  = isset( $row['Engine'] ) ? (string) $row['Engine'] : '';
			$support = isset( $row['Support'] ) ? strtoupper( (string) $row['Support'] ) : '';
			if ( 'INNODB' === strtoupper( $engine ) && in_array( $support, array( 'YES', 'DEFAULT' ), true ) ) {
				return true;
			}
		}

		return false;
	}
}
