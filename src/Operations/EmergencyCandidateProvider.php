<?php
/**
 * Guest-only Emergency Mode decision candidates.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionCandidate;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConflictDetector;
use Codeprint\CheckoutFirewall\Turnstile\VerifiedChallengeState;

final class EmergencyCandidateProvider {
	private EmergencyMode $mode;
	private TurnstileConfig $turnstile;
	private TurnstileConflictDetector $conflicts;
	private VerifiedChallengeState $verified;
	private ?ChallengeConfig $challenges;

	public function __construct( EmergencyMode $mode, TurnstileConfig $turnstile, TurnstileConflictDetector $conflicts, VerifiedChallengeState $verified, ?ChallengeConfig $challenges = null ) {
		$this->mode       = $mode;
		$this->turnstile  = $turnstile;
		$this->conflicts  = $conflicts;
		$this->verified   = $verified;
		$this->challenges = $challenges;
	}

	public function register(): void {
		add_filter( 'checkout_firewall_decision_candidates', array( $this, 'candidates' ), 7, 2 );
	}

	/**
	 * Add the Emergency candidate when the request requires it.
	 *
	 * @param mixed $candidates Existing candidates.
	 * @return mixed
	 */
	public function candidates( $candidates, CheckoutContext $context ) {
		if ( ! is_array( $candidates ) || ! $this->mode->is_active() || $context->is_logged_in() || $this->verified->has( $context ) ) {
			return $candidates;
		}
		if ( ( null !== $this->challenges && $this->challenges->is_available() ) || ( null === $this->challenges && $this->turnstile->is_active() && ! $this->conflicts->has_conflict() ) ) {
			$candidates[] = new DecisionCandidate( DecisionAction::CHALLENGE, null !== $this->challenges ? ReasonCode::CHALLENGE_REQUIRED : ReasonCode::TURNSTILE_REQUIRED );
			return $candidates;
		}
		$this->mode->stop();
		Health::record( 'emergency', 'prerequisite_unavailable' );
		return $candidates;
	}
}
