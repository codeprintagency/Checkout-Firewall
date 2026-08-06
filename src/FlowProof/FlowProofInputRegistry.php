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
	 * Normalized Classic field value.
	 */
	private ?string $classic_value = null;
	private bool $classic_invalid  = false;
	/**
	 * Exact untrusted Store API values by order ID.
	 *
	 * @var array<int,array{present:bool,invalid:bool,value:?string}>
	 */
	private array $orders = array();

	/**
	 * Record one normalized field value.
	 *
	 * @throws \InvalidArgumentException When Store API context has no order ID.
	 */
	public function record( CheckoutContext $context, ?string $value, bool $present, bool $invalid = false ): void {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			$this->classic_present = $present;
			$this->classic_value   = $value;
			$this->classic_invalid = $invalid;
			return;
		}
		$order_id = $context->order_id();
		if ( null === $order_id ) {
			throw new \InvalidArgumentException( 'Store API proof input requires an order ID.' );
		}
		$this->orders[ $order_id ] = array(
			'present' => $present,
			'invalid' => $invalid,
			'value'   => $value,
		);
	}

	/**
	 * Read the exact value associated with a checkout context.
	 *
	 * @return array{present:bool,invalid:bool,value:?string}
	 */
	public function read( CheckoutContext $context ): array {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			return array(
				'present' => $this->classic_present,
				'invalid' => $this->classic_invalid,
				'value'   => $this->classic_value,
			);
		}
		$order_id = $context->order_id();
		return null === $order_id || ! isset( $this->orders[ $order_id ] )
			? array(
				'present' => false,
				'invalid' => false,
				'value'   => null,
			)
			: $this->orders[ $order_id ];
	}
}
