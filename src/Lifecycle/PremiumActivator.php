<?php
/**
 * Premium replacement activation while the Free bootstrap owns this request.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Lifecycle;

use Codeprint\CheckoutFirewall\Commercial\CodeType;
use Codeprint\CheckoutFirewall\Commercial\PackageArbitrator;

final class PremiumActivator {
	/**
	 * Deactivate the exact Free basename and run the shared activation lifecycle.
	 *
	 * @param mixed $network_wide WordPress network activation flag.
	 */
	public static function activate( $network_wide = false ): void {
		PackageArbitrator::prepare_activation( CodeType::PREMIUM );
		Activator::activate( $network_wide );
	}
}
