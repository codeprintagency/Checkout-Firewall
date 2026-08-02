<?php
/**
 * Request-local event retention discriminator.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

final class EventRetentionState {
	private int $days = 0;

	/** Enable the closed Premium retention class. */
	public function enable_premium(): void {
		$this->days = 90;
	}

	/** Return the closed storage discriminator. */
	public function days(): int {
		return 90 === $this->days ? 90 : 0;
	}
}
