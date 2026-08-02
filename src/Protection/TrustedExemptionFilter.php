<?php
/**
 * Narrow final candidate exemption filter.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Decision\DecisionCandidate;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;

final class TrustedExemptionFilter {
	private const USER_REASONS = array(
		ReasonCode::VELOCITY_IP_EXCEEDED,
		ReasonCode::VELOCITY_EMAIL_EXCEEDED,
		ReasonCode::VELOCITY_SESSION_EXCEEDED,
		ReasonCode::VELOCITY_COMBINED_EXCEEDED,
		ReasonCode::PAYMENT_FAILURE_LOCKOUT,
	);
	private const IP_REASONS   = array(
		ReasonCode::VELOCITY_IP_EXCEEDED,
		ReasonCode::VELOCITY_COMBINED_EXCEEDED,
		ReasonCode::PAYMENT_FAILURE_LOCKOUT,
	);

	public function __construct( private TrustedExemptionMatcher $matcher, private TrustedExemptionState $state ) {}

	public function register(): void {
		add_filter( 'checkout_firewall_decision_candidates', array( $this, 'filter' ), PHP_INT_MAX, 2 );
	}

	/**
	 * Remove only exemption-eligible automatic decision candidates.
	 *
	 * @param mixed           $candidates Candidate collection.
	 * @param CheckoutContext $context    Current checkout context.
	 * @return mixed
	 */
	public function filter( $candidates, CheckoutContext $context ): mixed {
		unset( $context );
		if ( ! is_array( $candidates ) ) {
			return $candidates;
		}
		$match = $this->matcher->match();
		if ( null === $match ) {
			return $candidates;
		}
		$allowed = 'user' === $match['subject_type'] ? self::USER_REASONS : self::IP_REASONS;
		$kept    = array();
		$removed = false;
		foreach ( $candidates as $candidate ) {
			if ( $candidate instanceof DecisionCandidate && in_array( $candidate->reason(), $allowed, true ) ) {
				$removed = true;
				continue;
			}
			$kept[] = $candidate;
		}
		if ( $removed ) {
			$this->state->record( $match );
		}
		return $kept;
	}
}
