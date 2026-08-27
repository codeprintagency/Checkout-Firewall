<?php
/**
 * Merchant-selected checkout challenge presentation policy.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

final class ChallengePolicy {
	public const OPTION        = 'checkout_firewall_challenge_policy';
	public const ADAPTIVE      = 'adaptive';
	public const ALWAYS_GUESTS = 'always_guests';
	public const POLICIES      = array( self::ADAPTIVE, self::ALWAYS_GUESTS );

	public function current(): string {
		$value = get_option( self::OPTION, self::ADAPTIVE );
		return is_string( $value ) && in_array( $value, self::POLICIES, true ) ? $value : self::ADAPTIVE;
	}

	public function always_for_guests(): bool {
		return self::ALWAYS_GUESTS === $this->current();
	}

	public function save( string $policy ): void {
		if ( ! in_array( $policy, self::POLICIES, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported checkout challenge policy.' );
		}
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, $policy, '', false );
			return;
		}
		update_option( self::OPTION, $policy, false );
	}
}
