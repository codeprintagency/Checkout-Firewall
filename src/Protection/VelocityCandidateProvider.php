<?php
/**
 * Central-engine M4 local protection candidates.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Data\CounterType;
use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionCandidate;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Turnstile\VerifiedChallengeState;

final class VelocityCandidateProvider {
	private VerifiedProofState $verified;
	private IdentityRegistry $identities;
	private CounterRepository $counters;
	private BlockRepository $blocks;
	private GatewayHealth $health;
	private ?VerifiedChallengeState $turnstile;
	private ?VelocityObservationState $observations;
	private ?CheckoutSignalState $signals;

	public function __construct( VerifiedProofState $verified, IdentityRegistry $identities, CounterRepository $counters, BlockRepository $blocks, GatewayHealth $health, ?VerifiedChallengeState $turnstile = null, ?VelocityObservationState $observations = null, ?CheckoutSignalState $signals = null ) {
		$this->verified     = $verified;
		$this->identities   = $identities;
		$this->counters     = $counters;
		$this->blocks       = $blocks;
		$this->health       = $health;
		$this->turnstile    = $turnstile;
		$this->observations = $observations;
		$this->signals      = $signals;
	}

	public function register(): void {
		add_filter( 'checkout_firewall_decision_candidates', array( $this, 'candidates' ), 20, 2 );
	}

	/**
	 * Append M4 candidates after an attributable proof is consumed.
	 *
	 * @param mixed $candidates Existing candidates.
	 * @return mixed
	 */
	public function candidates( $candidates, CheckoutContext $context ): mixed {
		if ( ! is_array( $candidates )
			|| ( ! $this->verified->has( $context ) && ( null === $this->turnstile || ! $this->turnstile->has( $context ) ) )
		) {
			return $candidates;
		}
		$identities = $this->identities->read( $context );
		if ( array() === $identities ) {
			return $candidates;
		}
		$gateway = $context->gateway_id();
		$outage  = '' !== $gateway && $this->health->is_outage( $gateway );
		$active  = $this->blocks->active( $identities );
		if ( is_array( $active ) ) {
			$automatic = ReasonCode::PAYMENT_FAILURE_LOCKOUT === ( $active['reason_code'] ?? '' );
			if ( $automatic && $outage && $this->health->source( $gateway ) === ( $active['source'] ?? '' ) ) {
				$this->blocks->release( $identities, $this->health->source( $gateway ) );
				$candidates[] = new DecisionCandidate( DecisionAction::ALLOW, ReasonCode::GATEWAY_OUTAGE_OVERRIDE, array( 'window_seconds' => ProtectionPolicy::OUTAGE_WINDOW ) );
			} else {
				$candidates[] = new DecisionCandidate(
					DecisionAction::BLOCK,
					$automatic ? ReasonCode::PAYMENT_FAILURE_LOCKOUT : ReasonCode::EXPLICIT_LOCAL_BLOCK
				);
			}
		}

		$this->counters->increment( $identities, CounterType::CHECKOUT_ATTEMPT );
		$trusted    = $this->trusted();
		$reduced    = false;
		$challenged = null !== $this->turnstile && $this->turnstile->has( $context );
		if ( ! $outage && ! $challenged && '' !== $gateway && $this->recent_failure_requires_challenge( $identities, $gateway ) ) {
			$candidates[] = new DecisionCandidate(
				DecisionAction::CHALLENGE,
				ReasonCode::PAYMENT_FAILURE_CHALLENGE,
				array( 'gateway' => $gateway )
			);
		}
		foreach ( $identities as $type => $identity ) {
			if ( IdentifierType::GATEWAY === $type ) {
				continue;
			}
			$standard           = ProtectionPolicy::velocity( $type, false );
			$policy             = ProtectionPolicy::velocity( $type, $trusted );
			$throttle           = ProtectionPolicy::throttle( $type, $trusted );
			$risk               = $this->one( $identity, CounterType::CHECKOUT_ATTEMPT, $policy['window'], '' );
			$success            = $this->one( $identity, CounterType::PAYMENT_SUCCESS, $policy['window'], '' );
			$effective          = ProtectionPolicy::effective( $risk, $success, 2 );
			$decision_effective = $effective + ( null !== $this->signals && $this->signals->is_suspicious( $context ) ? 1 : 0 );
			if ( null !== $this->observations ) {
				$this->observations->record( $type, $effective, $policy['threshold'], $policy['window'], $trusted );
			}
			if ( $trusted && $effective >= $standard['threshold'] && $effective < $policy['threshold'] ) {
				$reduced = true;
			}
			$throttle_risk      = $this->one( $identity, CounterType::CHECKOUT_ATTEMPT, $throttle['window'], '' );
			$throttle_success   = $this->one( $identity, CounterType::PAYMENT_SUCCESS, $throttle['window'], '' );
			$throttle_effective = ProtectionPolicy::effective( $throttle_risk, $throttle_success, 2 );
			if ( $throttle_effective >= $throttle['threshold'] ) {
				$candidates[] = new DecisionCandidate(
					DecisionAction::BLOCK,
					ReasonCode::VELOCITY_THROTTLED,
					array(
						'identity_type'  => $type,
						'count'          => $throttle_effective,
						'threshold'      => $throttle['threshold'],
						'window_seconds' => $throttle['window'],
						'trusted'        => $trusted,
					)
				);
			} elseif ( $decision_effective >= $policy['threshold'] && ! $challenged ) {
				$candidates[] = new DecisionCandidate(
					DecisionAction::CHALLENGE,
					$this->reason( $type ),
					array(
						'count'             => $effective,
						'threshold'         => $policy['threshold'],
						'window_seconds'    => $policy['window'],
						'trusted'           => $trusted,
						'automation_signal' => null !== $this->signals ? $this->signals->reason( $context ) : '',
					)
				);
			}
		}
		if ( $reduced ) {
			$candidates[] = new DecisionCandidate( DecisionAction::ALLOW, ReasonCode::TRUSTED_CUSTOMER_REDUCTION, array( 'multiplier' => 2 ) );
		}
		if ( $outage && ! $this->contains_outage( $candidates ) ) {
			$candidates[] = new DecisionCandidate( DecisionAction::ALLOW, ReasonCode::GATEWAY_OUTAGE_OVERRIDE, array( 'window_seconds' => ProtectionPolicy::OUTAGE_WINDOW ) );
		}
		return $candidates;
	}

	/**
	 * Challenge the next attributable gateway attempt before the lockout limit.
	 *
	 * @param array<int,array<string,mixed>> $identities Keyed identities.
	 */
	private function recent_failure_requires_challenge( array $identities, string $gateway ): bool {
		foreach ( array( IdentifierType::SESSION, IdentifierType::IP_EMAIL ) as $type ) {
			if ( ! isset( $identities[ $type ] ) ) {
				continue;
			}
			$identity = $identities[ $type ];
			if ( $this->one( $identity, CounterType::GATEWAY_DECLINE, ProtectionPolicy::DECLINE_WINDOW, $gateway ) >= 1
				|| $this->one( $identity, CounterType::OTHER_FAILURE, ProtectionPolicy::OTHER_WINDOW, $gateway ) >= 2
			) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Read one identity total.
	 *
	 * @param array<string,mixed> $identity Keyed identity.
	 */
	private function one( array $identity, int $type, int $window, string $gateway ): int {
		$values = $this->counters->totals( array( (int) $identity['identifier_type'] => $identity ), $type, $window, $gateway );
		return (int) reset( $values );
	}

	private function trusted(): bool {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		$woocommerce = WC();
		$customer    = isset( $woocommerce->customer ) ? $woocommerce->customer : null;
		return is_object( $customer ) && method_exists( $customer, 'get_is_paying_customer' ) && (bool) $customer->get_is_paying_customer();
	}

	private function reason( int $type ): string {
		$reasons = array(
			IdentifierType::IP       => ReasonCode::VELOCITY_IP_EXCEEDED,
			IdentifierType::EMAIL    => ReasonCode::VELOCITY_EMAIL_EXCEEDED,
			IdentifierType::SESSION  => ReasonCode::VELOCITY_SESSION_EXCEEDED,
			IdentifierType::IP_EMAIL => ReasonCode::VELOCITY_COMBINED_EXCEEDED,
		);
		if ( ! isset( $reasons[ $type ] ) ) {
			throw new \InvalidArgumentException( 'Unsupported velocity reason.' );
		}
		return $reasons[ $type ];
	}

	/**
	 * Determine whether the candidate list already includes an outage signal.
	 *
	 * @param array<mixed> $candidates Decision candidates.
	 */
	private function contains_outage( array $candidates ): bool {
		foreach ( $candidates as $candidate ) {
			if ( $candidate instanceof DecisionCandidate && ReasonCode::GATEWAY_OUTAGE_OVERRIDE === $candidate->reason() ) {
				return true;
			}
		}
			return false;
	}
}
