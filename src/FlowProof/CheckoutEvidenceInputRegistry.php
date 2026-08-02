<?php
/**
 * Request-local checkout evidence input registry.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;

final class CheckoutEvidenceInputRegistry {
	/**
	 * Surface-keyed untrusted evidence inputs.
	 *
	 * @var array<string,array{token:mixed,field:mixed,value:mixed,present:bool}>
	 */
	private array $values = array();

	public function record( CheckoutContext $context, mixed $token, mixed $field, mixed $value, bool $present ): void {
		$this->values[ $this->key( $context ) ] = array(
			'token'   => $token,
			'field'   => $field,
			'value'   => $value,
			'present' => $present,
		);
	}

	/**
	 * Read one surface's untrusted evidence.
	 *
	 * @return array{token:mixed,field:mixed,value:mixed,present:bool}
	 */
	public function read( CheckoutContext $context ): array {
		return $this->values[ $this->key( $context ) ] ?? array(
			'token'   => null,
			'field'   => null,
			'value'   => null,
			'present' => false,
		);
	}

	private function key( CheckoutContext $context ): string {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			return 'classic';
		}
		$order_id = $context->order_id();
		if ( null === $order_id ) {
			throw new \InvalidArgumentException( 'Store API checkout evidence requires an order ID.' );
		}
		return 'order:' . $order_id;
	}
}
