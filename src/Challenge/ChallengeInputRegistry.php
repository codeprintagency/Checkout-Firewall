<?php
/**
 * Request-local untrusted challenge input isolation.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;

final class ChallengeInputRegistry {
	/**
	 * Surface-keyed untrusted inputs.
	 *
	 * @var array<string,array{token:?string,state:?string,present:bool,invalid:bool}>
	 */
	private array $values = array();

	public function record( CheckoutContext $context, ?string $token, ?string $state, bool $present, bool $invalid = false ): void {
		$this->values[ $this->key( $context ) ] = array(
			'token'   => $token,
			'state'   => $state,
			'present' => $present,
			'invalid' => $invalid,
		);
	}

	/**
	 * Read one surface's untrusted input.
	 *
	 * @return array{token:?string,state:?string,present:bool,invalid:bool}
	 */
	public function read( CheckoutContext $context ): array {
		return $this->values[ $this->key( $context ) ] ?? array(
			'token'   => null,
			'state'   => null,
			'present' => false,
			'invalid' => false,
		);
	}

	private function key( CheckoutContext $context ): string {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			return 'classic';
		}
		$order_id = $context->order_id();
		if ( null === $order_id ) {
			throw new \InvalidArgumentException( 'Challenge Store API input requires an order ID.' );
		}
		return 'order:' . $order_id;
	}
}
