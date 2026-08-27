<?php
/**
 * Validate low-confidence honeypot and render-time evidence.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Protection\CheckoutSignalState;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class CheckoutEvidenceProvider {
	private CheckoutEvidenceInputRegistry $inputs;
	private CheckoutEvidenceService $service;
	private CheckoutSignalState $state;

	public function __construct( CheckoutEvidenceInputRegistry $inputs, CheckoutEvidenceService $service, CheckoutSignalState $state ) {
		$this->inputs  = $inputs;
		$this->service = $service;
		$this->state   = $state;
	}

	public function register(): void {
		add_filter( 'checkout_firewall_decision_candidates', array( $this, 'candidates' ), 15, 2 );
	}

	public function candidates( mixed $candidates, CheckoutContext $context ): mixed {
		if ( ! is_array( $candidates ) ) {
			return $candidates;
		}
		$input = $this->inputs->read( $context );
		if ( ! $input['present'] ) {
			return $candidates;
		}
		if ( $input['invalid'] ) {
			$this->state->mark( $context, 'evidence_malformed', 2 );
			return $candidates;
		}
		try {
			$reason = $this->service->classify( $input['token'], $input['field'], $input['value'], CartBinding::from_woocommerce() );
			if ( '' !== $reason ) {
				$strong = in_array( $reason, array( 'evidence_malformed', 'evidence_invalid', 'honeypot_filled', 'submitted_impossibly_fast' ), true );
				$this->state->mark( $context, $reason, $strong ? 2 : 1 );
			}
		} catch ( \Throwable $exception ) {
			// Evidence collection is advisory and fails open.
			SafeLogger::exception( 'checkout_evidence_failed', $exception );
		}
		return $candidates;
	}
}
