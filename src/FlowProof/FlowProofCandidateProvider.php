<?php
/**
 * Central-engine checkout-flow proof candidate provider.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionCandidate;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Protection\VerifiedProofState;
use Codeprint\CheckoutFirewall\Turnstile\VerifiedChallengeState;

final class FlowProofCandidateProvider {
	private FlowProofInputRegistry $inputs;
	private FlowProofService $service;
	private ConsumedTokenRepository $tokens;
	private VerifiedProofState $verified;
	private ?VerifiedChallengeState $turnstile;

	public function __construct( FlowProofInputRegistry $inputs, ?FlowProofService $service = null, ?ConsumedTokenRepository $tokens = null, ?VerifiedProofState $verified = null, ?VerifiedChallengeState $turnstile = null ) {
		$this->inputs    = $inputs;
		$this->service   = $service ?? new FlowProofService();
		$this->tokens    = $tokens ?? new ConsumedTokenRepository();
		$this->verified  = $verified ?? new VerifiedProofState();
		$this->turnstile = $turnstile;
	}

	public function register(): void {
		add_filter( 'checkout_firewall_decision_candidates', array( $this, 'candidates' ), 10, 2 );
	}

	/**
	 * Append the first-party proof decision candidate.
	 *
	 * @param mixed $candidates Existing candidate collection.
	 * @return mixed
	 */
	public function candidates( $candidates, CheckoutContext $context ) {
		if ( ! is_array( $candidates ) ) {
			return $candidates;
		}

		$input = $this->inputs->read( $context );
		if ( $input['invalid'] ) {
			$candidates[] = self::candidate( DecisionAction::BLOCK, ReasonCode::FLOW_PROOF_INVALID, 'invalid' );
			return $candidates;
		}
		if ( ! $input['present'] || '' === $input['value'] || null === $input['value'] ) {
			if ( null === $this->turnstile || ! $this->turnstile->has( $context ) ) {
				$candidates[] = self::candidate( DecisionAction::CHALLENGE, ReasonCode::FLOW_PROOF_MISSING, 'missing' );
			}
			return $candidates;
		}
		if ( strlen( $input['value'] ) > FlowProofService::MAX_TOKEN_SIZE ) {
			$candidates[] = self::candidate( DecisionAction::BLOCK, ReasonCode::FLOW_PROOF_INVALID, 'invalid' );
			return $candidates;
		}

		try {
			$validation = $this->service->validate( $input['value'], CartBinding::from_woocommerce() );
		} catch ( InvalidProofException $exception ) {
			$candidates[] = self::candidate( DecisionAction::BLOCK, ReasonCode::FLOW_PROOF_INVALID, 'invalid' );
			return $candidates;
		}
		if ( 'expired' === $validation['status'] ) {
			if ( null === $this->turnstile || ! $this->turnstile->has( $context ) ) {
				$candidates[] = self::candidate( DecisionAction::CHALLENGE, ReasonCode::FLOW_PROOF_EXPIRED, 'expired' );
			}
			return $candidates;
		}
		if ( ! $this->tokens->consume( $validation ) ) {
			$candidates[] = self::candidate( DecisionAction::BLOCK, ReasonCode::FLOW_PROOF_REPLAYED, 'replayed' );
		} else {
			$this->verified->mark( $context );
		}

		return $candidates;
	}

	private static function candidate( string $action, string $reason, string $state ): DecisionCandidate {
		return new DecisionCandidate( $action, $reason, array( 'proof_state' => $state ) );
	}
}
