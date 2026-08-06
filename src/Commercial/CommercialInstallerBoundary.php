<?php
/**
 * Disable the Freemius in-dashboard Premium package installer.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class CommercialInstallerBoundary {
	/**
	 * Remove the vendor callback after SDK initialization on its matching AJAX request.
	 */
	public static function suppress( object $sdk ): bool {
		if ( ! method_exists( $sdk, 'get_ajax_action' ) || ! method_exists( $sdk, '_install_premium_version_ajax_action' ) ) {
			return false;
		}
		$action = $sdk->get_ajax_action( 'install_premium_version' );
		if ( ! is_string( $action ) || '' === $action ) {
			return false;
		}
		return remove_action( 'wp_ajax_' . $action, array( $sdk, '_install_premium_version_ajax_action' ) );
	}
}
