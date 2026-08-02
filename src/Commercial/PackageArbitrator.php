<?php
/**
 * Exact Free/Premium replacement and one-engine arbitration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class PackageArbitrator {
	public const FREE_BASENAME    = 'checkout-firewall/checkout-firewall.php';
	public const PREMIUM_BASENAME = 'checkout-firewall-premium/checkout-firewall.php';

	/**
	 * Decide whether this exact package owns the shared runtime.
	 *
	 * @param mixed $active_plugins WordPress active plugin option.
	 */
	public static function should_boot( string $current_basename, $active_plugins ): bool {
		$active = is_array( $active_plugins ) ? $active_plugins : array();
		return self::FREE_BASENAME !== $current_basename || ! in_array( self::PREMIUM_BASENAME, $active, true );
	}

	public static function prepare_activation( string $code_type ): void {
		if ( CodeType::PREMIUM !== CodeType::normalize( $code_type ) || ! function_exists( 'deactivate_plugins' ) ) {
			return;
		}
		deactivate_plugins( self::FREE_BASENAME, true, false );
	}
}
