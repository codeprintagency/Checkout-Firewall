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
		try {
			$reason = $this->service->classify( $input['token'], $input['field'], $input['value'], CartBinding::from_woocommerce() );
			if ( '' !== $reason ) {
				$this->state->mark( $context, $reason );
			}
		} catch ( \Throwable $exception ) {
			$this->state->mark( $context, 'evidence_unavailable' );
		}
		return $candidates;
	}
}
