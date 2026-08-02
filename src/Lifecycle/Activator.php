<?php
/**
 * Plugin activation lifecycle.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Lifecycle;

use Codeprint\CheckoutFirewall\Compatibility\Requirements;
use Codeprint\CheckoutFirewall\Commercial\CodeType;
use Codeprint\CheckoutFirewall\Commercial\PackageArbitrator;
use Codeprint\CheckoutFirewall\Database\Migrator;
use Codeprint\CheckoutFirewall\Scheduler\CleanupScheduler;
use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;

final class Activator {
	/**
	 * Activate the plugin.
	 *
	 * @param mixed $network_wide WordPress network activation flag.
	 */
	public static function activate( $network_wide = false ): void {
		if ( (bool) $network_wide || is_multisite() ) {
			self::abort( Requirements::MULTISITE_UNSUPPORTED );
		}

		$code_type = defined( 'CWF_CODE_TYPE' ) && is_string( CWF_CODE_TYPE ) ? CWF_CODE_TYPE : CodeType::FREE;
		PackageArbitrator::prepare_activation( $code_type );

		$failure = Requirements::activation_failure();
		if ( null !== $failure ) {
			self::abort( $failure );
		}

		try {
			$fresh    = Migrator::installed_version() < 1 && false === get_option( 'cwf_plugin_version', false );
			$migrator = new Migrator();
			if ( ! $migrator->migrate() ) {
				self::abort( 'schema_unhealthy' );
			}

			$key_store = new KeyStore();
			if ( ! $key_store->initialize() || ! $key_store->validate_references() ) {
				Health::record( 'key', 'verification_failed' );
				self::abort( 'key_unhealthy' );
			}

			Health::clear( 'key' );
			if ( $fresh ) {
				( new OperatingMode() )->initialize_fresh();
			}
			Migrator::write_option( 'cwf_plugin_version', CWF_VERSION );
			add_option( 'cwf_delete_data_on_uninstall', false, '', false );

			if ( class_exists( '\\ActionScheduler' )
				&& \ActionScheduler::is_initialized()
			) {
				CleanupScheduler::ensure_schedules();
			} else {
				delete_option( CleanupScheduler::VERSION_OPTION );
			}
		} catch ( \Throwable $exception ) {
			Health::record( 'activation', 'exception' );
			self::abort( 'activation_failed' );
		}
	}

	private static function abort( string $failure_code ): void {
		$message = self::failure_message( $failure_code );

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\\WP_CLI' ) ) {
			\WP_CLI::error( $message );
		}

		wp_die(
			esc_html( $message ),
			esc_html__( 'Checkout Firewall activation failed', 'checkout-firewall' ),
			array(
				'back_link' => true,
				'response'  => 500,
			)
		);
	}

	private static function failure_message( string $failure_code ): string {
		$messages = array(
			Requirements::PHP_UNSUPPORTED         => __( 'Checkout Firewall requires PHP 8.0 or newer.', 'checkout-firewall' ),
			Requirements::WORDPRESS_UNSUPPORTED   => __( 'Checkout Firewall requires WordPress 6.8 or newer.', 'checkout-firewall' ),
			Requirements::WOOCOMMERCE_MISSING     => __( 'Checkout Firewall requires WooCommerce to be installed and active.', 'checkout-firewall' ),
			Requirements::WOOCOMMERCE_UNSUPPORTED => __( 'Checkout Firewall requires WooCommerce 10.7 or newer.', 'checkout-firewall' ),
			Requirements::MULTISITE_UNSUPPORTED   => __( 'Checkout Firewall does not support WordPress multisite in this version.', 'checkout-firewall' ),
			Requirements::INNODB_UNAVAILABLE      => __( 'Checkout Firewall requires an available InnoDB database engine.', 'checkout-firewall' ),
			Requirements::RANDOMNESS_UNAVAILABLE  => __( 'Checkout Firewall could not access secure system randomness.', 'checkout-firewall' ),
			'schema_unhealthy'                    => __( 'Checkout Firewall could not create and verify its database tables.', 'checkout-firewall' ),
			'key_unhealthy'                       => __( 'Checkout Firewall could not initialize its local security key safely.', 'checkout-firewall' ),
		);

		return $messages[ $failure_code ] ?? __( 'Checkout Firewall activation could not complete safely.', 'checkout-firewall' );
	}
}
