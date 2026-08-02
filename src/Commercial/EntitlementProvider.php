<?php
/**
 * Local entitlement provider contract.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

interface EntitlementProvider {
	public function entitlement(): Entitlement;
}
