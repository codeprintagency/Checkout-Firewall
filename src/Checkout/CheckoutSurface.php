<?php
/**
 * Supported checkout surface registry.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Checkout;

final class CheckoutSurface {
	public const CLASSIC         = 'classic';
	public const STORE_API       = 'store_api_checkout';
	public const STORE_API_ORDER = 'store_api_order';

	/**
	 * Return every supported checkout surface.
	 *
	 * @return list<string>
	 */
	public static function all(): array {
		return array( self::CLASSIC, self::STORE_API, self::STORE_API_ORDER );
	}

	public static function is_valid( string $surface ): bool {
		return in_array( $surface, self::all(), true );
	}
}
