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

$cwf_plugin_file     = __FILE__;
$cwf_plugin_basename = plugin_basename( $cwf_plugin_file );

if ( ! class_exists( \Codeprint\CheckoutFirewall\Autoloader::class, false ) ) {
	require_once __DIR__ . '/src/Autoloader.php';
}

try {
	\Codeprint\CheckoutFirewall\Autoloader::register( __DIR__ );
	$cwf_active_plugins = get_option( 'active_plugins', array() );
	if ( ! \Codeprint\CheckoutFirewall\Commercial\PackageArbitrator::should_boot( $cwf_plugin_basename, $cwf_active_plugins ) ) {
		return;
	}

	if ( ( defined( 'CWF_PLUGIN_FILE' ) && CWF_PLUGIN_FILE !== $cwf_plugin_file )
		|| ( defined( 'CWF_PLUGIN_BASENAME' ) && CWF_PLUGIN_BASENAME !== $cwf_plugin_basename )
	) {
		if ( \Codeprint\CheckoutFirewall\Commercial\PackageArbitrator::PREMIUM_BASENAME === $cwf_plugin_basename ) {
			register_activation_hook( $cwf_plugin_file, array( \Codeprint\CheckoutFirewall\Lifecycle\PremiumActivator::class, 'activate' ) );
		}
		return;
	}

	$cwf_commercial_config = \Codeprint\CheckoutFirewall\Commercial\FreemiusConfig::load( __DIR__ );
	defined( 'CWF_VERSION' ) || define( 'CWF_VERSION', '1.0.0' );
	defined( 'CWF_PLUGIN_FILE' ) || define( 'CWF_PLUGIN_FILE', $cwf_plugin_file );
	defined( 'CWF_PLUGIN_BASENAME' ) || define( 'CWF_PLUGIN_BASENAME', $cwf_plugin_basename );
	defined( 'CWF_CODE_TYPE' ) || define( 'CWF_CODE_TYPE', $cwf_commercial_config->code_type() );

	\Codeprint\CheckoutFirewall\Commercial\CommercialBootstrap::initialize( __DIR__ );

	register_activation_hook( CWF_PLUGIN_FILE, array( \Codeprint\CheckoutFirewall\Lifecycle\Activator::class, 'activate' ) );
	register_deactivation_hook( CWF_PLUGIN_FILE, array( \Codeprint\CheckoutFirewall\Lifecycle\Deactivator::class, 'deactivate' ) );

	add_action( 'before_woocommerce_init', array( \Codeprint\CheckoutFirewall\Compatibility\HposDeclaration::class, 'declare' ) );
	add_action( 'before_woocommerce_init', array( \Codeprint\CheckoutFirewall\Compatibility\CheckoutBlocksDeclaration::class, 'declare' ) );
	add_action( 'plugins_loaded', array( \Codeprint\CheckoutFirewall\Plugin::class, 'boot' ) );
} catch ( \Throwable $cwf_exception ) {
	if ( class_exists( \Codeprint\CheckoutFirewall\Support\SafeLogger::class ) ) {
		\Codeprint\CheckoutFirewall\Support\SafeLogger::exception( 'bootstrap_failed', $cwf_exception );
	} elseif ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
		error_log( 'Checkout Firewall: bootstrap_failed.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
	}
}

unset( $cwf_plugin_file, $cwf_plugin_basename, $cwf_active_plugins, $cwf_commercial_config, $cwf_exception );
