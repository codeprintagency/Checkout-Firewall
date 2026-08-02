<?php
/**
 * Provider used whenever Premium authorization is unavailable.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class FreeEntitlementProvider implements EntitlementProvider {
	private string $state;

	public function __construct( string $state = Entitlement::FREE ) {
		$this->state = $state;
	}

	public function entitlement(): Entitlement {
		return Entitlement::free( $this->state );
	}
}
