<?php
/**
 * Keep vendor support links out of the WooCommerce submenu.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class CommercialMenuBoundary {
	/**
	 * Register the scoped Freemius visibility filter when supported.
	 */
	public static function register( object $sdk ): bool {
		if ( ! method_exists( $sdk, 'add_filter' ) ) {
			return false;
		}
		$sdk->add_filter( 'is_submenu_visible', array( self::class, 'submenu_visible' ), 10, 2 );
		return true;
	}

	/**
	 * Hide only the vendor contact form and public support-forum link.
	 */
	public static function submenu_visible( bool $visible, string $menu_id ): bool {
		return in_array( $menu_id, array( 'contact', 'support' ), true ) ? false : $visible;
	}
}
