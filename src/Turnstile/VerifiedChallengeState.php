<?php
/**
 * Request-local marker for successful selected-provider recovery.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;

final class VerifiedChallengeState {
	private bool $classic = false;
	/**
	 * Store API order IDs verified in this request.
	 *
	 * @var array<int,bool>
	 */
	private array $orders = array();

	public function mark( CheckoutContext $context ): void {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			$this->classic = true;
			return;
		}
		if ( null !== $context->order_id() ) {
			$this->orders[ $context->order_id() ] = true;
		}
	}

	public function has( CheckoutContext $context ): bool {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			return $this->classic;
		}
		return null !== $context->order_id() && isset( $this->orders[ $context->order_id() ] );
	}
}
