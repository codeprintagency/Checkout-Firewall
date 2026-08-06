<?php
/**
 * Records one final memoized checkout decision.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Decision\DecisionResult;
use Codeprint\CheckoutFirewall\Support\SafeLogger;
use Codeprint\CheckoutFirewall\Operations\FreeIncidentObserver;

final class DecisionEventRecorder {
	private EventRepository $events;
	private IdentityRegistry $identities;
	private ?FreeIncidentObserver $incidents;

	public function __construct( EventRepository $events, IdentityRegistry $identities, ?FreeIncidentObserver $incidents = null ) {
		$this->events     = $events;
		$this->identities = $identities;
		$this->incidents  = $incidents;
	}

	public function record( DecisionResult $result, CheckoutContext $context, bool $observed = false ): void {
		try {
			$identities = $this->identities->read( $context );
			$recorded   = $this->events->record( $result, $context, $identities, null, $observed );
			if ( $recorded && null !== $this->incidents ) {
				$this->incidents->observe( $result, $observed );
			}
			if ( $recorded ) {
				do_action( 'checkout_firewall_decision_recorded', $result, $context, $identities, $observed );
			}
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'decision_event_failed', $exception );
		}
	}
}
