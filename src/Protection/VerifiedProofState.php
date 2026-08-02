<?php
/**
 * Request-local marker for a successfully consumed checkout-flow proof.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;

final class VerifiedProofState {
	private bool $classic = false;
	/**
	 * Store API order IDs with a consumed proof in this request.
	 *
	 * @var array<int,bool>
	 */
	private array $orders = array();

	public function mark( CheckoutContext $context ): void {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			$this->classic = true;
			return;
		}
		$order_id = $context->order_id();
		if ( null !== $order_id ) {
			$this->orders[ $order_id ] = true;
		}
	}

	public function has( CheckoutContext $context ): bool {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			return $this->classic;
		}
		$order_id = $context->order_id();
		return null !== $order_id && isset( $this->orders[ $order_id ] );
	}
}
