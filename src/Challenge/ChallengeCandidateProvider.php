<?php
/**
 * Validate selected-provider recovery through the central decision engine.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionCandidate;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Recaptcha\SiteverifyClient as RecaptchaClient;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Turnstile\SiteverifyClient as TurnstileClient;
use Codeprint\CheckoutFirewall\Turnstile\SiteverifyResult;
use Codeprint\CheckoutFirewall\Turnstile\VerifiedChallengeState;

final class ChallengeCandidateProvider {
	public const MAX_STATE = 64;

	private ChallengeInputRegistry $inputs;
	private ChallengeConfig $config;
	private ChallengeCoordinator $coordinator;
	private LocalProofService $local;
	private TurnstileClient $turnstile;
	private RecaptchaClient $recaptcha;
	private VerifiedChallengeState $verified;
	private ?EmergencyMode $emergency;

	public function __construct(
		ChallengeInputRegistry $inputs,
		ChallengeConfig $config,
		ChallengeCoordinator $coordinator,
		LocalProofService $local,
		TurnstileClient $turnstile,
		RecaptchaClient $recaptcha,
		VerifiedChallengeState $verified,
		?EmergencyMode $emergency = null
	) {
		$this->inputs      = $inputs;
		$this->config      = $config;
		$this->coordinator = $coordinator;
		$this->local       = $local;
		$this->turnstile   = $turnstile;
		$this->recaptcha   = $recaptcha;
		$this->verified    = $verified;
		$this->emergency   = $emergency;
	}

	public function register(): void {
		add_filter( 'checkout_firewall_decision_candidates', array( $this, 'candidates' ), 5, 2 );
	}

	public function candidates( mixed $candidates, CheckoutContext $context ): mixed {
		if ( ! is_array( $candidates ) ) {
			return $candidates;
		}
		$input = $this->inputs->read( $context );
		if ( ! $input['present'] ) {
			return $candidates;
		}
		if ( $input['invalid'] || null === $input['token'] || null === $input['state'] || '' === $input['token'] || '' === $input['state']
			|| strlen( $input['token'] ) > LocalProofService::MAX_PAYLOAD || strlen( $input['state'] ) > self::MAX_STATE
		) {
			return $this->invalid( $candidates, 'invalid_input' );
		}
		$submission = $this->coordinator->submission( $context, $input['state'] );
		if ( null === $submission ) {
			return $this->coordinator->attempts_exhausted( $context, $input['state'] ) ? $candidates : $this->invalid( $candidates, 'invalid_state' );
		}
		$result = $this->verify( $submission, $input['token'], $input['state'] );
		if ( $result->is_valid() ) {
			$this->verified->mark( $context );
			$this->coordinator->consume();
			Health::clear( 'challenge' );
			Health::clear( $submission['provider'] );
			$this->config->recovery()->clear( $submission['provider'] );
			return $candidates;
		}
		if ( SiteverifyResult::INVALID_SECRET === $result->status() ) {
			if ( null !== $this->emergency && $this->emergency->is_active() ) {
				$this->emergency->stop();
			}
			if ( ChallengeConfig::TURNSTILE === $submission['provider'] ) {
				$this->config->turnstile()->disable();
			} elseif ( ChallengeConfig::RECAPTCHA === $submission['provider'] ) {
				$this->config->recaptcha()->disable();
			}
			Health::record( $submission['provider'], 'invalid_secret' );
			return $candidates;
		}
		if ( SiteverifyResult::UNAVAILABLE === $result->status() ) {
			Health::record( $submission['provider'], $result->classification() );
			$this->config->recovery()->record_unavailable( $submission['provider'], $result->classification() );
			return $candidates;
		}
		return $this->invalid( $candidates, $result->classification(), true );
	}

	/**
	 * Verify one bounded provider submission.
	 *
	 * @param array{provider:string,hostname:string,cdata:string,expires_at:int} $submission Challenge context.
	 */
	private function verify( array $submission, string $token, string $state ): SiteverifyResult {
		if ( ChallengeConfig::LOCAL === $submission['provider'] ) {
			return new SiteverifyResult(
				$this->local->verify( $token, $state, $submission['expires_at'], time() ) ? SiteverifyResult::VALID : SiteverifyResult::INVALID,
				'local_proof'
			);
		}
		if ( ChallengeConfig::TURNSTILE === $submission['provider'] ) {
			$credentials = $this->config->turnstile()->credentials();
			return $this->turnstile->verify( $token, $credentials['secret_key'], $submission['hostname'], ChallengeCoordinator::ACTION, $submission['cdata'] );
		}
		if ( ChallengeConfig::RECAPTCHA === $submission['provider'] ) {
			$credentials = $this->config->recaptcha()->credentials();
			return $this->recaptcha->verify( $token, $credentials['secret_key'], $submission['hostname'] );
		}
		return new SiteverifyResult( SiteverifyResult::UNAVAILABLE, 'provider_unavailable' );
	}

	/**
	 * Append one attributable invalid-challenge candidate.
	 *
	 * @param array<int|string,mixed> $candidates Existing candidates.
	 * @return array<int|string,mixed>
	 */
	private function invalid( array $candidates, string $state, bool $attributable = false ): array {
		$signals = array( 'challenge_state' => substr( sanitize_key( $state ), 0, 32 ) );
		if ( $attributable ) {
			$signals['challenge_attributable'] = true;
		}
		$candidates[] = new DecisionCandidate( DecisionAction::CHALLENGE, ReasonCode::CHALLENGE_INVALID, $signals );
		return $candidates;
	}
}
