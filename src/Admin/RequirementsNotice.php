<?php
/**
 * Administrator requirement and health notices.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Compatibility\Requirements;

final class RequirementsNotice {
	private static ?string $failure_code = null;

	public static function register( string $failure_code ): void {
		self::$failure_code = $failure_code;
		add_action( 'admin_notices', array( self::class, 'render' ) );
		add_action( 'network_admin_notices', array( self::class, 'render' ) );
	}

	public static function render(): void {
		$capability = is_network_admin() ? 'manage_network_plugins' : 'activate_plugins';
		if ( ! current_user_can( $capability ) || null === self::$failure_code ) {
			return;
		}

		$message = self::message( self::$failure_code );
		printf(
			'<div class="notice notice-error"><p>%s</p></div>',
			esc_html( $message )
		);
	}

	public static function message( string $failure_code ): string {
		switch ( $failure_code ) {
			case Requirements::PHP_UNSUPPORTED:
				return __( 'Checkout Firewall requires PHP 8.0 or newer.', 'checkout-firewall' );
			case Requirements::WORDPRESS_UNSUPPORTED:
				return __( 'Checkout Firewall requires WordPress 6.8 or newer.', 'checkout-firewall' );
			case Requirements::WOOCOMMERCE_MISSING:
				return __( 'Checkout Firewall requires WooCommerce to be installed and active.', 'checkout-firewall' );
			case Requirements::WOOCOMMERCE_UNSUPPORTED:
				return __( 'Checkout Firewall requires WooCommerce 10.7 or newer.', 'checkout-firewall' );
			case Requirements::MULTISITE_UNSUPPORTED:
				return __( 'Checkout Firewall does not support WordPress multisite in this version.', 'checkout-firewall' );
			case Requirements::INNODB_UNAVAILABLE:
				return __( 'Checkout Firewall requires an available InnoDB database engine.', 'checkout-firewall' );
			case Requirements::RANDOMNESS_UNAVAILABLE:
				return __( 'Checkout Firewall could not access secure system randomness.', 'checkout-firewall' );
			case 'schema_outdated':
				return __( 'Checkout Firewall needs a database update. Visit this page again or use WP-CLI from a maintenance context.', 'checkout-firewall' );
			case 'schema_unhealthy':
			case 'key_unhealthy':
			default:
				return __( 'Checkout Firewall could not initialize safely. Review the site logs and retry from a maintenance context.', 'checkout-firewall' );
		}
	}
}
