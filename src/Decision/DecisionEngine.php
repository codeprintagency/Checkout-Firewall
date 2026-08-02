<?php
/**
 * Central checkout decision reducer.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Decision;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class DecisionEngine {
	private const MAX_CANDIDATES = 32;

	/**
	 * Optional testable candidate provider.
	 *
	 * @var null|\Closure(CheckoutContext):mixed
	 */
	private ?\Closure $candidate_provider;

	public function __construct( ?callable $candidate_provider = null ) {
		$this->candidate_provider = null === $candidate_provider ? null : \Closure::fromCallable( $candidate_provider );
	}

	public function evaluate( CheckoutContext $context ): DecisionResult {
		try {
			$candidates = null === $this->candidate_provider
				? apply_filters( 'checkout_firewall_decision_candidates', array(), $context )
				: ( $this->candidate_provider )( $context );

			if ( ! is_array( $candidates ) || count( $candidates ) > self::MAX_CANDIDATES ) {
				throw new \UnexpectedValueException( 'Invalid checkout decision candidate collection.' );
			}

			return $this->reduce( $candidates );
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'decision_evaluation_failed', $exception );
			return new DecisionResult( DecisionAction::ALLOW, ReasonCode::INTERNAL_ERROR_FAIL_OPEN );
		}
	}

	/**
	 * Reduce a validated candidate collection.
	 *
	 * @param array<mixed> $candidates Candidate collection.
	 * @throws \UnexpectedValueException When an entry is not a typed candidate.
	 */
	private function reduce( array $candidates ): DecisionResult {
		$best = null;
		$seen = array();

		foreach ( $candidates as $candidate ) {
			if ( ! $candidate instanceof DecisionCandidate ) {
				throw new \UnexpectedValueException( 'Untyped checkout decision candidate.' );
			}

			$key = $candidate->action() . ':' . $candidate->reason();
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;

			if ( null === $best || $this->outranks( $candidate, $best ) ) {
				$best = $candidate;
			}
		}

		if ( null === $best ) {
			return new DecisionResult( DecisionAction::ALLOW, ReasonCode::CHECKOUT_ALLOWED );
		}

		return new DecisionResult( $best->action(), $best->reason(), $best->signals() );
	}

	private function outranks( DecisionCandidate $candidate, DecisionCandidate $current ): bool {
		$candidate_action = DecisionAction::rank( $candidate->action() );
		$current_action   = DecisionAction::rank( $current->action() );

		if ( $candidate_action !== $current_action ) {
			return $candidate_action > $current_action;
		}

		return ReasonCatalog::priority( $candidate->reason() ) > ReasonCatalog::priority( $current->reason() );
	}
}
