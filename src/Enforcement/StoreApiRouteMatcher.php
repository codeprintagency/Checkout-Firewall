<?php
/**
 * Exact Store API checkout route matcher.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Enforcement;

use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;

final class StoreApiRouteMatcher {
	public static function surface( string $method, string $route ): ?string {
		if ( 'POST' !== strtoupper( $method ) ) {
			return null;
		}
		if ( '/wc/store/v1/checkout' === $route ) {
			return CheckoutSurface::STORE_API;
		}
		if ( 1 === preg_match( '#^/wc/store/v1/checkout/[1-9][0-9]*$#D', $route ) ) {
			return CheckoutSurface::STORE_API_ORDER;
		}
		return null;
	}
}
