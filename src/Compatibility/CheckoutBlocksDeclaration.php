<?php
/**
 * WooCommerce Cart and Checkout Blocks compatibility declaration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Compatibility;

final class CheckoutBlocksDeclaration {
	public static function declare(): void {
		$class = '\\Automattic\\WooCommerce\\Utilities\\FeaturesUtil';

		if ( class_exists( $class ) ) {
			$class::declare_compatibility( 'cart_checkout_blocks', CWF_PLUGIN_FILE, true );
		}
	}
}
