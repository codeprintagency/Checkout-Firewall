<?php
/**
 * Projects one calculated decision through the selected operating mode.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Enforcement;

use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionResult;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;

final class EnforcementDisposition {
	public function __construct( private OperatingMode $mode ) {}

	public function is_observed( DecisionResult $calculated ): bool {
		return $this->mode->is_observing() && ! $calculated->allows_checkout();
	}

	public function enforce( DecisionResult $calculated ): DecisionResult {
		if ( ! $this->mode->is_observing() || $calculated->allows_checkout() ) {
			return $calculated;
		}
		return new DecisionResult(
			DecisionAction::ALLOW,
			ReasonCode::CHECKOUT_ALLOWED,
			array(
				'observed_action' => $calculated->action(),
				'observed_reason' => $calculated->reason(),
			)
		);
	}
}
