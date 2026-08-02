<?php
/**
 * Final central checkout decision.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Decision;

final class DecisionResult {
	private string $action;
	private string $reason;
	private string $customer_message;
	private string $admin_explanation;

	/**
	 * Bounded safe signals.
	 *
	 * @var array<string,string|int|float|bool|null>
	 */
	private array $signals;

	/**
	 * Create a final decision from first-party catalog data.
	 *
	 * @param array<string,string|int|float|bool|null> $signals Bounded safe signals.
	 * @throws \InvalidArgumentException When the action and reason are incompatible.
	 */
	public function __construct( string $action, string $reason, array $signals = array() ) {
		if ( ReasonCatalog::action( $reason ) !== $action ) {
			throw new \InvalidArgumentException( 'Invalid checkout decision result.' );
		}

		$this->action            = $action;
		$this->reason            = $reason;
		$this->customer_message  = ReasonCatalog::customer_message( $action, $reason );
		$this->admin_explanation = ReasonCatalog::admin_explanation( $reason );
		$this->signals           = $signals;
	}

	public function action(): string {
		return $this->action;
	}

	public function reason(): string {
		return $this->reason;
	}

	public function customer_message(): string {
		return $this->customer_message;
	}

	public function admin_explanation(): string {
		return $this->admin_explanation;
	}

	/**
	 * Return bounded safe signals.
	 *
	 * @return array<string,string|int|float|bool|null>
	 */
	public function signals(): array {
		return $this->signals;
	}

	public function allows_checkout(): bool {
		return DecisionAction::ALLOW === $this->action;
	}
}
