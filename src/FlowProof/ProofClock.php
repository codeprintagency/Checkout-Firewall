<?php
/**
 * Testable integer clock for proof lifetimes.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

final class ProofClock {
	/**
	 * Optional deterministic timestamp provider.
	 *
	 * @var null|\Closure():int
	 */
	private ?\Closure $provider;

	public function __construct( ?callable $provider = null ) {
		$this->provider = null === $provider ? null : \Closure::fromCallable( $provider );
	}

	public function now(): int {
		$now = null === $this->provider ? time() : ( $this->provider )();
		if ( $now < 1 ) {
			throw new \RuntimeException( 'Checkout-flow proof clock is invalid.' );
		}
		return $now;
	}
}
