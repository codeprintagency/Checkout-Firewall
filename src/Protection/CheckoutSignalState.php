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
	 * @var array<string,array{points:int,reasons:list<string>}>
	 */
	private array $states = array();

	public function mark( CheckoutContext $context, string $reason, int $points = 1 ): void {
		$key    = $this->key( $context );
		$reason = substr( sanitize_key( $reason ), 0, 32 );
		if ( '' === $reason || $points < 1 ) {
			return;
		}
		$current = $this->states[ $key ] ?? array(
			'points'  => 0,
			'reasons' => array(),
		);
		if ( ! in_array( $reason, $current['reasons'], true ) && count( $current['reasons'] ) < 4 ) {
			$current['reasons'][] = $reason;
			$current['points']    = min( 4, $current['points'] + min( 2, $points ) );
		}
		$this->states[ $key ] = $current;
	}

	public function is_suspicious( CheckoutContext $context ): bool {
		return $this->points( $context ) > 0;
	}

	public function reason( CheckoutContext $context ): string {
		return implode( ',', $this->states[ $this->key( $context ) ]['reasons'] ?? array() );
	}

	public function points( CheckoutContext $context ): int {
		return $this->states[ $this->key( $context ) ]['points'] ?? 0;
	}

	public function requires_challenge( CheckoutContext $context ): bool {
		return $this->points( $context ) >= 2;
	}

	private function key( CheckoutContext $context ): string {
		return CheckoutSurface::CLASSIC === $context->surface() ? 'classic' : 'order:' . ( $context->order_id() ?? 0 );
	}
}
