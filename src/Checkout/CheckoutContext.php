<?php
/**
 * Bounded checkout evaluation context.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Checkout;

final class CheckoutContext {
	private string $surface;
	private bool $logged_in;
	private int $cart_item_count;
	private bool $needs_payment;
	private int $total_minor;
	private string $gateway_id;
	private ?int $order_id;

	public function __construct(
		string $surface,
		bool $logged_in,
		int $cart_item_count,
		bool $needs_payment,
		int $total_minor,
		string $gateway_id = '',
		?int $order_id = null
	) {
		if ( ! CheckoutSurface::is_valid( $surface ) ) {
			throw new \InvalidArgumentException( 'Unsupported checkout surface.' );
		}
		if ( $cart_item_count < 0 || $total_minor < 0 || ( null !== $order_id && $order_id < 1 ) ) {
			throw new \InvalidArgumentException( 'Checkout context values are outside their bounds.' );
		}

		$this->surface         = $surface;
		$this->logged_in       = $logged_in;
		$this->cart_item_count = $cart_item_count;
		$this->needs_payment   = $needs_payment;
		$this->total_minor     = $total_minor;
		$this->gateway_id      = substr( sanitize_key( $gateway_id ), 0, 64 );
		$this->order_id        = $order_id;
	}

	public function surface(): string {
		return $this->surface;
	}

	public function is_logged_in(): bool {
		return $this->logged_in;
	}

	public function cart_item_count(): int {
		return $this->cart_item_count;
	}

	public function needs_payment(): bool {
		return $this->needs_payment;
	}

	public function total_minor(): int {
		return $this->total_minor;
	}

	public function gateway_id(): string {
		return $this->gateway_id;
	}

	public function order_id(): ?int {
		return $this->order_id;
	}
}
