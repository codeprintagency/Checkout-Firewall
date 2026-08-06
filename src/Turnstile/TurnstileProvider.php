<?php
/**
 * Validate submitted Turnstile recovery through the central engine.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionCandidate;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Support\Health;

final class TurnstileProvider {
	public const MAX_STATE = 64;

	private TurnstileInputRegistry $inputs;
	private TurnstileConfig $config;
	private TurnstileConflictDetector $conflicts;
	private ChallengeCoordinator $challenges;
	private SiteverifyClient $client;
	private VerifiedChallengeState $verified;

	public function __construct(
		TurnstileInputRegistry $inputs,
		TurnstileConfig $config,
		TurnstileConflictDetector $conflicts,
		ChallengeCoordinator $challenges,
		SiteverifyClient $client,
		VerifiedChallengeState $verified
	) {
		$this->inputs     = $inputs;
		$this->config     = $config;
		$this->conflicts  = $conflicts;
		$this->challenges = $challenges;
		$this->client     = $client;
		$this->verified   = $verified;
	}

	public function register(): void {
		add_filter( 'checkout_firewall_decision_candidates', array( $this, 'candidates' ), 5, 2 );
	}

	/**
	 * Validate a submitted recovery before local proof and velocity providers.
	 *
	 * @param mixed $candidates Existing candidate list.
	 * @return mixed
	 */
	public function candidates( $candidates, CheckoutContext $context ) {
		if ( ! is_array( $candidates ) ) {
			return $candidates;
		}
		$input = $this->inputs->read( $context );
		if ( ! $input['present'] || ! $this->config->is_active() || $this->conflicts->has_conflict() ) {
			return $candidates;
		}
		if ( $input['invalid'] || null === $input['token'] || null === $input['state']
			|| '' === $input['token'] || strlen( $input['token'] ) > SiteverifyClient::MAX_TOKEN
			|| '' === $input['state'] || strlen( $input['state'] ) > self::MAX_STATE
		) {
			return $this->invalid( $candidates, 'invalid_input' );
		}
		$submission = $this->challenges->submission( $context, $input['state'] );
		if ( null === $submission ) {
			if ( $this->challenges->attempts_exhausted( $context, $input['state'] ) ) {
				return $candidates;
			}
			return $this->invalid( $candidates, 'invalid_state' );
		}
		$credentials = $this->config->credentials();
		$result      = $this->client->verify(
			$input['token'],
			$credentials['secret_key'],
			$submission['hostname'],
			ChallengeCoordinator::ACTION,
			$submission['cdata']
		);
		if ( $result->is_valid() ) {
			$this->verified->mark( $context );
			$this->challenges->consume();
			Health::clear( 'turnstile' );
			return $candidates;
		}
		if ( SiteverifyResult::INVALID_SECRET === $result->status() ) {
			$this->config->disable();
			Health::record( 'turnstile', 'invalid_secret' );
			return $candidates;
		}
		if ( SiteverifyResult::UNAVAILABLE === $result->status() ) {
			Health::record( 'turnstile', $result->classification() );
			return $candidates;
		}
		return $this->invalid( $candidates, $result->classification(), true );
	}

	/**
	 * Append one bounded invalid-challenge candidate.
	 *
	 * @param array<mixed> $candidates Existing candidates.
	 * @return array<mixed>
	 */
	private function invalid( array $candidates, string $state, bool $attributable = false ): array {
		$signals = array( 'turnstile_state' => $state );
		if ( $attributable ) {
			$signals['turnstile_attributable'] = true;
		}
		$candidates[] = new DecisionCandidate( DecisionAction::CHALLENGE, ReasonCode::TURNSTILE_INVALID, $signals );
		return $candidates;
	}
}
