<?php
/**
 * Request-local Turnstile input registry.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;

final class TurnstileInputRegistry {
	/**
	 * Inputs keyed by checkout surface/order.
	 *
	 * @var array<string,array{token:mixed,state:mixed,present:bool}>
	 */
	private array $values = array();

	/**
	 * Record exact untrusted checkout input.
	 *
	 * @param mixed $token Untrusted token.
	 * @param mixed $state Untrusted state.
	 */
	public function record( CheckoutContext $context, $token, $state, bool $present ): void {
		$this->values[ $this->key( $context ) ] = array(
			'token'   => $token,
			'state'   => $state,
			'present' => $present,
		);
	}

	/**
	 * Read exact input for one evaluation context.
	 *
	 * @return array{token:mixed,state:mixed,present:bool}
	 */
	public function read( CheckoutContext $context ): array {
		return $this->values[ $this->key( $context ) ] ?? array(
			'token'   => null,
			'state'   => null,
			'present' => false,
		);
	}

	private function key( CheckoutContext $context ): string {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			return 'classic';
		}
		$order_id = $context->order_id();
		if ( null === $order_id ) {
			throw new \InvalidArgumentException( 'Turnstile Store API input requires an order ID.' );
		}
		return 'order:' . $order_id;
	}
}
