<?php
/**
 * WooCommerce compatibility declarations.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Compatibility;

final class HposDeclaration {
	public static function declare(): void {
		$class = '\\Automattic\\WooCommerce\\Utilities\\FeaturesUtil';

		if ( class_exists( $class ) ) {
			$class::declare_compatibility( 'custom_order_tables', CWF_PLUGIN_FILE, true );
		}
	}
}
