<?php
/**
 * Closed set of existing local services available to entitled Premium code.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Protection\GatewayObservationState;
use Codeprint\CheckoutFirewall\Protection\EventRetentionState;
use Codeprint\CheckoutFirewall\Protection\VelocityObservationState;
use Codeprint\CheckoutFirewall\Protection\VerifiedProofState;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConflictDetector;
use Codeprint\CheckoutFirewall\Turnstile\VerifiedChallengeState;

final class PremiumRuntimeContext {
	public VerifiedProofState $verified_proof;
	public VerifiedChallengeState $verified_challenge;
	public VelocityObservationState $velocity;
	public TurnstileConfig $turnstile;
	public TurnstileConflictDetector $conflicts;
	public EmergencyMode $emergency;
	public GatewayObservationState $gateway_observations;
	public EventRetentionState $event_retention;
	public ?ChallengeConfig $challenges;

	public function __construct(
		VerifiedProofState $verified_proof,
		VerifiedChallengeState $verified_challenge,
		VelocityObservationState $velocity,
		TurnstileConfig $turnstile,
		TurnstileConflictDetector $conflicts,
		EmergencyMode $emergency,
		?GatewayObservationState $gateway_observations = null,
		?EventRetentionState $event_retention = null,
		?ChallengeConfig $challenges = null
	) {
		$this->verified_proof       = $verified_proof;
		$this->verified_challenge   = $verified_challenge;
		$this->velocity             = $velocity;
		$this->turnstile            = $turnstile;
		$this->conflicts            = $conflicts;
		$this->emergency            = $emergency;
		$this->gateway_observations = $gateway_observations ?? new GatewayObservationState();
		$this->event_retention      = $event_retention ?? new EventRetentionState();
		$this->challenges           = $challenges;
	}

	public function challenge_available(): bool {
		return null !== $this->challenges
			? $this->challenges->is_available()
			: $this->turnstile->is_active() && ! $this->conflicts->has_conflict();
	}
}
