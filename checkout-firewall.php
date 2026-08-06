<?php
/**
 * Plugin Name: Checkout Firewall for WooCommerce
 * Plugin URI: https://checkoutfirewall.com
 * Description: Helps protect WooCommerce checkout from automated abuse before payment processing.
 * Version: 1.0.0
 * Requires at least: 6.8
 * Requires PHP: 8.0
 * Author: Codeprint
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: checkout-firewall
 * Domain Path: /languages
 * Requires Plugins: woocommerce
 * WC requires at least: 10.7
 * WC tested up to: 10.9
 *
 * @package Codeprint\CheckoutFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$checkout_firewall_plugin_file     = __FILE__;
$checkout_firewall_plugin_basename = plugin_basename( $checkout_firewall_plugin_file );

if ( ! class_exists( \Codeprint\CheckoutFirewall\Autoloader::class, false ) ) {
	require_once __DIR__ . '/src/Autoloader.php';
}

try {
	\Codeprint\CheckoutFirewall\Autoloader::register( __DIR__ );
	$checkout_firewall_active_plugins = get_option( 'active_plugins', array() );
	if ( ! \Codeprint\CheckoutFirewall\Commercial\PackageArbitrator::should_boot( $checkout_firewall_plugin_basename, $checkout_firewall_active_plugins ) ) {
		return;
	}

	if ( ( defined( 'CHECKOUT_FIREWALL_PLUGIN_FILE' ) && CHECKOUT_FIREWALL_PLUGIN_FILE !== $checkout_firewall_plugin_file )
		|| ( defined( 'CHECKOUT_FIREWALL_PLUGIN_BASENAME' ) && CHECKOUT_FIREWALL_PLUGIN_BASENAME !== $checkout_firewall_plugin_basename )
	) {
		return;
	}

	$checkout_firewall_commercial_config = \Codeprint\CheckoutFirewall\Commercial\FreemiusConfig::load( __DIR__ );
	defined( 'CHECKOUT_FIREWALL_VERSION' ) || define( 'CHECKOUT_FIREWALL_VERSION', '1.0.0' );
	defined( 'CHECKOUT_FIREWALL_PLUGIN_FILE' ) || define( 'CHECKOUT_FIREWALL_PLUGIN_FILE', $checkout_firewall_plugin_file );
	defined( 'CHECKOUT_FIREWALL_PLUGIN_BASENAME' ) || define( 'CHECKOUT_FIREWALL_PLUGIN_BASENAME', $checkout_firewall_plugin_basename );
	defined( 'CHECKOUT_FIREWALL_CODE_TYPE' ) || define( 'CHECKOUT_FIREWALL_CODE_TYPE', $checkout_firewall_commercial_config->code_type() );

	\Codeprint\CheckoutFirewall\Commercial\CommercialBootstrap::initialize( __DIR__ );
	if ( ! function_exists( 'checkout_firewall_fs' ) ) {
		/** Return the contained Freemius SDK instance. */
		function checkout_firewall_fs(): ?object {
			return \Codeprint\CheckoutFirewall\Commercial\CommercialBootstrap::sdk();
		}
	}

	$checkout_firewall_activation_callback = array( \Codeprint\CheckoutFirewall\Lifecycle\Activator::class, 'activate' );
	register_activation_hook( CHECKOUT_FIREWALL_PLUGIN_FILE, $checkout_firewall_activation_callback );
	register_deactivation_hook( CHECKOUT_FIREWALL_PLUGIN_FILE, array( \Codeprint\CheckoutFirewall\Lifecycle\Deactivator::class, 'deactivate' ) );

	add_action( 'before_woocommerce_init', array( \Codeprint\CheckoutFirewall\Compatibility\HposDeclaration::class, 'declare' ) );
	add_action( 'before_woocommerce_init', array( \Codeprint\CheckoutFirewall\Compatibility\CheckoutBlocksDeclaration::class, 'declare' ) );
	add_action( 'plugins_loaded', array( \Codeprint\CheckoutFirewall\Plugin::class, 'boot' ) );
} catch ( \Throwable $checkout_firewall_exception ) {
	if ( class_exists( \Codeprint\CheckoutFirewall\Support\SafeLogger::class ) ) {
		\Codeprint\CheckoutFirewall\Support\SafeLogger::exception( 'bootstrap_failed', $checkout_firewall_exception );
	} elseif ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
		error_log( 'Checkout Firewall: bootstrap_failed.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
	}
}

unset( $checkout_firewall_plugin_file, $checkout_firewall_plugin_basename, $checkout_firewall_active_plugins, $checkout_firewall_commercial_config, $checkout_firewall_activation_callback, $checkout_firewall_sdk, $checkout_firewall_exception );
