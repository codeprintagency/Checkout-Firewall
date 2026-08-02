<?php
/**
 * Request-scoped checkout decision memoization.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Enforcement;

use Codeprint\CheckoutFirewall\Decision\DecisionResult;

final class RequestDecisionState {
	private ?DecisionResult $classic = null;

	/**
	 * Decisions keyed by positive order ID.
	 *
	 * @var array<int,DecisionResult>
	 */
	private array $orders = array();

	public function classic(): ?DecisionResult {
		return $this->classic;
	}

	public function record_classic( DecisionResult $result ): void {
		$this->classic = $result;
	}

	public function order( int $order_id ): ?DecisionResult {
		return $this->orders[ $order_id ] ?? null;
	}

	public function record_order( int $order_id, DecisionResult $result ): void {
		if ( $order_id > 0 ) {
			$this->orders[ $order_id ] = $result;
		}
	}
}
