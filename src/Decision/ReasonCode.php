<?php
/**
 * Stable checkout decision reason registry.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Decision;

final class ReasonCode {
	public const CHECKOUT_ALLOWED           = 'CHECKOUT_ALLOWED';
	public const EXPLICIT_LOCAL_BLOCK       = 'EXPLICIT_LOCAL_BLOCK';
	public const FLOW_PROOF_REPLAYED        = 'FLOW_PROOF_REPLAYED';
	public const FLOW_PROOF_INVALID         = 'FLOW_PROOF_INVALID';
	public const PAYMENT_FAILURE_LOCKOUT    = 'PAYMENT_FAILURE_LOCKOUT';
	public const EMERGENCY_MODE             = 'EMERGENCY_MODE';
	public const VELOCITY_COMBINED_EXCEEDED = 'VELOCITY_COMBINED_EXCEEDED';
	public const VELOCITY_SESSION_EXCEEDED  = 'VELOCITY_SESSION_EXCEEDED';
	public const VELOCITY_EMAIL_EXCEEDED    = 'VELOCITY_EMAIL_EXCEEDED';
	public const VELOCITY_IP_EXCEEDED       = 'VELOCITY_IP_EXCEEDED';
	public const TURNSTILE_INVALID          = 'TURNSTILE_INVALID';
	public const TURNSTILE_REQUIRED         = 'TURNSTILE_REQUIRED';
	public const CHALLENGE_INVALID          = 'CHALLENGE_INVALID';
	public const CHALLENGE_REQUIRED         = 'CHALLENGE_REQUIRED';
	public const CHALLENGE_UNAVAILABLE      = 'CHALLENGE_UNAVAILABLE_THROTTLE';
	public const FLOW_PROOF_EXPIRED         = 'FLOW_PROOF_EXPIRED';
	public const FLOW_PROOF_MISSING         = 'FLOW_PROOF_MISSING';
	public const TRUSTED_CUSTOMER_REDUCTION = 'TRUSTED_CUSTOMER_REDUCTION';
	public const GATEWAY_OUTAGE_OVERRIDE    = 'GATEWAY_OUTAGE_OVERRIDE';
	public const INTERNAL_ERROR_FAIL_OPEN   = 'INTERNAL_ERROR_FAIL_OPEN';

	/**
	 * Highest tie priority first, after the default allow reason.
	 *
	 * @return list<string>
	 */
	public static function all(): array {
		return array(
			self::CHECKOUT_ALLOWED,
			self::EXPLICIT_LOCAL_BLOCK,
			self::FLOW_PROOF_REPLAYED,
			self::FLOW_PROOF_INVALID,
			self::PAYMENT_FAILURE_LOCKOUT,
			self::EMERGENCY_MODE,
			self::VELOCITY_COMBINED_EXCEEDED,
			self::VELOCITY_SESSION_EXCEEDED,
			self::VELOCITY_EMAIL_EXCEEDED,
			self::VELOCITY_IP_EXCEEDED,
			self::TURNSTILE_INVALID,
			self::TURNSTILE_REQUIRED,
			self::CHALLENGE_INVALID,
			self::CHALLENGE_REQUIRED,
			self::CHALLENGE_UNAVAILABLE,
			self::FLOW_PROOF_EXPIRED,
			self::FLOW_PROOF_MISSING,
			self::TRUSTED_CUSTOMER_REDUCTION,
			self::GATEWAY_OUTAGE_OVERRIDE,
			self::INTERNAL_ERROR_FAIL_OPEN,
		);
	}
}
