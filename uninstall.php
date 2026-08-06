<?php
/**
 * Checkout Firewall uninstall entry point.
 *
 * @package Codeprint\CheckoutFirewall
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/src/Autoloader.php';

try {
	\Codeprint\CheckoutFirewall\Autoloader::register( __DIR__ );
	\Codeprint\CheckoutFirewall\Lifecycle\Uninstaller::run();
} catch ( \Throwable $checkout_firewall_exception ) {
	if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
		error_log( 'Checkout Firewall: uninstall_failed.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
	}
}

unset( $checkout_firewall_exception );
