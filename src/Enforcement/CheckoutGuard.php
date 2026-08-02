<?php
/**
 * Coordinates central evaluation and request-scoped state.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Enforcement;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;
use Codeprint\CheckoutFirewall\Decision\DecisionEngine;
use Codeprint\CheckoutFirewall\Decision\DecisionResult;
use Codeprint\CheckoutFirewall\Protection\DecisionEventRecorder;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Support\SafeLogger;
use Codeprint\CheckoutFirewall\Challenge\ChallengeCoordinator;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;

final class CheckoutGuard {
	private DecisionEngine $engine;
	private RequestDecisionState $state;
	private ?DecisionEventRecorder $events;
	private ?ChallengeCoordinator $challenges;
	private EnforcementDisposition $disposition;

	public function __construct( ?DecisionEngine $engine = null, ?RequestDecisionState $state = null, ?DecisionEventRecorder $events = null, ?ChallengeCoordinator $challenges = null, ?OperatingMode $mode = null ) {
		$this->engine      = $engine ?? new DecisionEngine();
		$this->state       = $state ?? new RequestDecisionState();
		$this->events      = $events;
		$this->challenges  = $challenges;
		$this->disposition = new EnforcementDisposition( $mode ?? new OperatingMode() );
	}

	public function evaluate( CheckoutContext $context ): DecisionResult {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			$recorded = $this->state->classic();
			if ( null !== $recorded ) {
				return $recorded;
			}

			$calculated                        = $this->engine->evaluate( $context );
			list( $result, $event, $observed ) = $this->finalize( $calculated, $context );
			$this->state->record_classic( $result );
			if ( null !== $this->events ) {
				$this->events->record( $event, $context, $observed );
			}
			return $result;
		}

		$order_id = $context->order_id();
		if ( null === $order_id ) {
			throw new \InvalidArgumentException( 'Store API checkout context requires an order ID.' );
		}

		$recorded = $this->state->order( $order_id );
		if ( null !== $recorded ) {
			return $recorded;
		}

		$calculated                        = $this->engine->evaluate( $context );
		list( $result, $event, $observed ) = $this->finalize( $calculated, $context );
		$this->state->record_order( $order_id, $result );
		if ( null !== $this->events ) {
			$this->events->record( $event, $context, $observed );
		}
		return $result;
	}

	public function classic_result(): ?DecisionResult {
		return $this->state->classic();
	}

	public function order_result( int $order_id ): ?DecisionResult {
		return $this->state->order( $order_id );
	}

	/**
	 * Project a calculated decision through operating mode and challenge issuance.
	 *
	 * @return array{DecisionResult,DecisionResult,bool} Enforced result, event result, and observed flag.
	 */
	private function finalize( DecisionResult $calculated, CheckoutContext $context ): array {
		try {
			$observed = $this->disposition->is_observed( $calculated );
			$result   = $observed ? $this->disposition->enforce( $calculated ) : $this->issue_challenge( $calculated, $context );
			return array( $result, $observed ? $calculated : $result, $observed );
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'operating_mode_disposition_failed', $exception );
			$fail_open = new DecisionResult( DecisionAction::ALLOW, ReasonCode::INTERNAL_ERROR_FAIL_OPEN, array( 'source_reason' => $calculated->reason() ) );
			return array( $fail_open, $fail_open, false );
		}
	}

	private function issue_challenge( DecisionResult $result, CheckoutContext $context ): DecisionResult {
		if ( null === $this->challenges || DecisionAction::CHALLENGE !== $result->action() ) {
			return $result;
		}
		try {
			if ( ! $this->challenges->issue( $context ) ) {
				return new DecisionResult( DecisionAction::BLOCK, ReasonCode::CHALLENGE_UNAVAILABLE, array( 'source_reason' => $result->reason() ) );
			}
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'challenge_issue_failed', $exception );
			return new DecisionResult( DecisionAction::ALLOW, ReasonCode::INTERNAL_ERROR_FAIL_OPEN, array( 'source_reason' => $result->reason() ) );
		}
		return $result;
	}
}
