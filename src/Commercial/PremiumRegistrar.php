<?php
/**
 * The only entry point for generated Premium modules.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class PremiumRegistrar {
	public static function register( EntitlementProvider $provider, ?PremiumRuntimeContext $context = null ): bool {
		$entitlement = $provider->entitlement();
		if ( ! $entitlement->allows_premium()
			|| CodeType::PREMIUM !== $entitlement->code_type()
			|| Entitlement::ACTIVE_PAID !== $entitlement->state()
			|| ! in_array( $entitlement->plan(), array( 'pro', 'business', 'agency' ), true )
		) {
			return false;
		}
		$class = 'Codeprint\\CheckoutFirewall\\Premium\\BuildSentinel';
		if ( ! class_exists( $class ) ) {
			return false;
		}
		$class::register( $context );
		return true;
	}
}
