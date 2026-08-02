<?php
/**
 * Translate locally cached Freemius state into the closed product contract.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class FreemiusEntitlementProvider implements EntitlementProvider {
	private object $sdk;
	private string $code_type;
	/**
	 * Exact paid-plan allowlist.
	 *
	 * @var list<string>
	 */
	private array $plans;

	/**
	 * Create the local SDK adapter.
	 *
	 * @param list<string> $plans Exact paid-plan allowlist.
	 */
	public function __construct( object $sdk, string $code_type, array $plans ) {
		$this->sdk       = $sdk;
		$this->code_type = CodeType::normalize( $code_type );
		$this->plans     = $plans;
	}

	public function entitlement(): Entitlement {
		if ( CodeType::PREMIUM !== $this->code_type ) {
			return Entitlement::free();
		}

		try {
			if ( ! method_exists( $this->sdk, 'is_paying' ) || ! method_exists( $this->sdk, 'get_plan_name' ) ) {
				return new Entitlement( $this->code_type, Entitlement::INVALID, '', false );
			}
			$is_paying = (bool) $this->sdk->is_paying();
			$plan      = strtolower( (string) $this->sdk->get_plan_name() );
			if ( ! $is_paying ) {
				return new Entitlement( $this->code_type, Entitlement::MISSING, $plan, false );
			}
			$allowed = in_array( $plan, $this->plans, true );
			return new Entitlement( $this->code_type, $allowed ? Entitlement::ACTIVE_PAID : Entitlement::INVALID, $plan, $allowed );
		} catch ( \Throwable $exception ) {
			unset( $exception );
			return new Entitlement( $this->code_type, Entitlement::PROVIDER_ERROR, '', false );
		}
	}
}
