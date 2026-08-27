<?php
/**
 * Bounded browser-request evidence and central-engine challenge candidate.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionCandidate;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\FlowProof\CheckoutEvidenceInputRegistry;
use Codeprint\CheckoutFirewall\Security\RequestNormalizer;
use Codeprint\CheckoutFirewall\Turnstile\VerifiedChallengeState;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class AutomationEvidenceProvider {
	public function __construct(
		private CheckoutSignalState $state,
		private CheckoutEvidenceInputRegistry $inputs,
		private ?VerifiedChallengeState $verified = null
	) {}

	public function register(): void {
		add_filter( 'checkout_firewall_decision_candidates', array( $this, 'candidates' ), 17, 2 );
	}

	public function candidates( mixed $candidates, CheckoutContext $context ): mixed {
		if ( ! is_array( $candidates ) ) {
			return $candidates;
		}
		try {
			if ( CheckoutSurface::CLASSIC === $context->surface() || $this->inputs->read( $context )['present'] ) {
				$this->record_headers( $context );
			}
			if ( $this->state->requires_challenge( $context ) && ( null === $this->verified || ! $this->verified->has( $context ) ) ) {
				$candidates[] = new DecisionCandidate(
					DecisionAction::CHALLENGE,
					ReasonCode::AUTOMATION_EVIDENCE,
					array(
						'automation_signal' => $this->state->reason( $context ),
						'evidence_points'   => $this->state->points( $context ),
					)
				);
			}
		} catch ( \Throwable $exception ) {
			// Request evidence is advisory. Collection failures remain neutral.
			SafeLogger::exception( 'automation_evidence_failed', $exception );
		}
		return $candidates;
	}

	private function record_headers( CheckoutContext $context ): void {
		$headers = array(
			RequestNormalizer::server( 'HTTP_USER_AGENT', 512 ),
			RequestNormalizer::server( 'HTTP_ACCEPT', 512 ),
			RequestNormalizer::server( 'HTTP_ACCEPT_LANGUAGE', 256 ),
		);
		$missing = 0;
		foreach ( $headers as $header ) {
			if ( $header['invalid'] || null === $header['value'] || '' === $header['value'] ) {
				++$missing;
			}
		}
		if ( 3 === $missing ) {
			$this->state->mark( $context, 'browser_headers_absent', 2 );
		} elseif ( 2 === $missing ) {
			$this->state->mark( $context, 'browser_headers_sparse', 1 );
		}

		$fetch_site = RequestNormalizer::server( 'HTTP_SEC_FETCH_SITE', 32 );
		if ( ! $fetch_site['invalid'] && 'cross-site' === $fetch_site['value'] ) {
			$this->state->mark( $context, 'cross_site_mismatch', 1 );
			return;
		}
		$store_host = strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
		foreach ( array( 'HTTP_ORIGIN', 'HTTP_REFERER' ) as $name ) {
			$value = RequestNormalizer::server( $name, 2048 );
			if ( $value['invalid'] || null === $value['value'] || '' === $value['value'] ) {
				continue;
			}
			$host = strtolower( (string) wp_parse_url( $value['value'], PHP_URL_HOST ) );
			if ( '' !== $host && '' !== $store_host && ! hash_equals( $store_host, $host ) ) {
				$this->state->mark( $context, 'cross_site_mismatch', 1 );
				return;
			}
		}
	}
}
