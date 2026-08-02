<?php
/**
 * Request-local low-confidence checkout automation evidence.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;

final class CheckoutSignalState {
	/**
	 * Request-keyed suspicious signal classifications.
	 *
	 * @var array<string,string>
	 */
	private array $states = array();

	public function mark( CheckoutContext $context, string $reason ): void {
		$this->states[ $this->key( $context ) ] = substr( sanitize_key( $reason ), 0, 32 );
	}

	public function is_suspicious( CheckoutContext $context ): bool {
		return isset( $this->states[ $this->key( $context ) ] );
	}

	public function reason( CheckoutContext $context ): string {
		return $this->states[ $this->key( $context ) ] ?? '';
	}

	private function key( CheckoutContext $context ): string {
		return CheckoutSurface::CLASSIC === $context->surface() ? 'classic' : 'order:' . ( $context->order_id() ?? 0 );
	}
}
