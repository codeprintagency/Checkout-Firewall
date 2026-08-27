<?php
/**
 * Resolve whether a guest checkout should obtain a challenge before submit.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;

final class PreflightPolicy {
	public function __construct(
		private ChallengePolicy $policy,
		private ChallengeConfig $config,
		private OperatingMode $operating,
		private EmergencyMode $emergency
	) {}

	public function required(): bool {
		if ( is_user_logged_in() || ! $this->operating->is_standard() || ! $this->config->is_available() ) {
			return false;
		}
		$required = $this->policy->always_for_guests() || $this->emergency->is_active();
		/**
		 * Permit an entitled local Premium module to request preflight during its
		 * current attack state. Free remains complete without that module.
		 */
		return (bool) apply_filters( 'checkout_firewall_preflight_required', $required );
	}
}
