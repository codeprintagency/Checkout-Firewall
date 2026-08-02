<?php
/**
 * Request-scoped trusted-exemption disposition.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

final class TrustedExemptionState {
	/**
	 * Exemption that affected the current request.
	 *
	 * @var array<string,mixed>|null
	 */
	private ?array $exemption = null;

	/**
	 * Record the exemption that affected this request.
	 *
	 * @param array<string,mixed> $exemption Matched exemption row.
	 */
	public function record( array $exemption ): void {
		$this->exemption = $exemption;
	}

	/**
	 * Read the exemption that affected this request.
	 *
	 * @return array<string,mixed>|null
	 */
	public function read(): ?array {
		return $this->exemption;
	}
}
