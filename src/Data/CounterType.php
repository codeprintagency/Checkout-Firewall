<?php
/**
 * Append-only counter type registry.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Data;

final class CounterType {
	public const CHECKOUT_ATTEMPT       = 1;
	public const GATEWAY_DECLINE        = 2;
	public const OTHER_FAILURE          = 3;
	public const PAYMENT_SUCCESS        = 4;
	public const INTERVENTION_CHALLENGE = 5;
	public const INTERVENTION_BLOCK     = 6;
	public const OBSERVED_CHALLENGE     = 7;
	public const OBSERVED_BLOCK         = 8;
	public const FLOW_PROOF_MINT        = 9;
	public const CHALLENGE_DESCRIPTOR   = 10;

	/**
	 * Return every registered counter type.
	 *
	 * @return list<int>
	 */
	public static function all(): array {
		return array( self::CHECKOUT_ATTEMPT, self::GATEWAY_DECLINE, self::OTHER_FAILURE, self::PAYMENT_SUCCESS, self::INTERVENTION_CHALLENGE, self::INTERVENTION_BLOCK, self::OBSERVED_CHALLENGE, self::OBSERVED_BLOCK, self::FLOW_PROOF_MINT, self::CHALLENGE_DESCRIPTOR );
	}

	public static function is_valid( int $type ): bool {
		return in_array( $type, self::all(), true );
	}
}
