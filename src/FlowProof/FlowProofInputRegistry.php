<?php
/**
 * Request-local raw proof isolation.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;

final class FlowProofInputRegistry {
	private bool $classic_present = false;
	/**
	 * Exact untrusted Classic field value.
	 *
	 * @var mixed
	 */
	private $classic_value;
	/**
	 * Exact untrusted Store API values by order ID.
	 *
	 * @var array<int,array{present:bool,value:mixed}>
	 */
	private array $orders = array();

	/**
	 * Record one exact untrusted field value.
	 *
	 * @param mixed $value Exact untrusted field value.
	 * @throws \InvalidArgumentException When Store API context has no order ID.
	 */
	public function record( CheckoutContext $context, $value, bool $present ): void {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			$this->classic_present = $present;
			$this->classic_value   = $value;
			return;
		}
		$order_id = $context->order_id();
		if ( null === $order_id ) {
			throw new \InvalidArgumentException( 'Store API proof input requires an order ID.' );
		}
		$this->orders[ $order_id ] = array(
			'present' => $present,
			'value'   => $value,
		);
	}

	/**
	 * Read the exact value associated with a checkout context.
	 *
	 * @return array{present:bool,value:mixed}
	 */
	public function read( CheckoutContext $context ): array {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			return array(
				'present' => $this->classic_present,
				'value'   => $this->classic_value,
			);
		}
		$order_id = $context->order_id();
		return null === $order_id || ! isset( $this->orders[ $order_id ] )
			? array(
				'present' => false,
				'value'   => null,
			)
			: $this->orders[ $order_id ];
	}
}
