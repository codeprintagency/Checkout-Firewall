<?php
/**
 * Atomic intervention signals and async Free incident evaluation.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

use Codeprint\CheckoutFirewall\Data\CounterType;
use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionResult;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Protection\CounterRepository;
use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class FreeIncidentObserver {
	public const HOOK      = 'checkout_firewall_evaluate_free_incident';
	public const THRESHOLD = 10;
	public const WINDOW    = 600;

	public function __construct( private CounterRepository $counters, private FreeIncidentState $state, private FreeIncidentMailer $mailer, private ?KeyStore $keys = null ) {
		$this->keys = $keys ?? new KeyStore();
	}

	public function register(): void {
		add_action( self::HOOK, array( $this, 'evaluate' ), 10, 1 );
	}

	public function observe( DecisionResult $result, bool $observed ): void {
		if ( $result->allows_checkout() || in_array( $result->reason(), array( ReasonCode::CHECKOUT_ALLOWED, ReasonCode::INTERNAL_ERROR_FAIL_OPEN, ReasonCode::GATEWAY_OUTAGE_OVERRIDE ), true ) ) {
			return;
		}
		$type = $observed
			? ( DecisionAction::BLOCK === $result->action() ? CounterType::OBSERVED_BLOCK : CounterType::OBSERVED_CHALLENGE )
			: ( DecisionAction::BLOCK === $result->action() ? CounterType::INTERVENTION_BLOCK : CounterType::INTERVENTION_CHALLENGE );
		try {
			$this->counters->increment( array( IdentifierType::SITE => $this->site_identity() ), $type );
			$this->schedule();
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'free_incident_signal_failed', $exception );
		}
	}

	public function evaluate( string $bucket ): void {
		if ( 1 !== preg_match( '/^\d{10}$/D', $bucket ) ) {
			return;
		}
		try {
			$identity = array( IdentifierType::SITE => $this->site_identity() );
			$counts   = array(
				'enforced_challenge' => $this->total( $identity, CounterType::INTERVENTION_CHALLENGE ),
				'enforced_block'     => $this->total( $identity, CounterType::INTERVENTION_BLOCK ),
				'observed_challenge' => $this->total( $identity, CounterType::OBSERVED_CHALLENGE ),
				'observed_block'     => $this->total( $identity, CounterType::OBSERVED_BLOCK ),
			);
			if ( array_sum( $counts ) >= self::THRESHOLD ) {
				$this->mailer->queue( $this->state->open( $counts ) );
			}
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'free_incident_evaluation_failed', $exception );
		}
	}

	/**
	 * Sum a bounded site counter window.
	 *
	 * @param array<int,array<string,mixed>> $identity Site identity map.
	 */
	private function total( array $identity, int $type ): int {
		$values = $this->counters->totals( $identity, $type, self::WINDOW );
		return (int) reset( $values );
	}

	/**
	 * Derive the local site identity used for incident counters.
	 *
	 * @return array<string,mixed>
	 * @throws \RuntimeException When the site host cannot be resolved.
	 */
	private function site_identity(): array {
		$host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		$host = is_string( $host ) ? strtolower( rtrim( $host, '.' ) ) : '';
		if ( '' === $host ) {
			throw new \RuntimeException( 'Site identity host is unavailable.' );
		}
		return array_merge(
			array(
				'identifier_type'      => IdentifierType::SITE,
				'retained_identifiers' => $this->keys->hash_identifier_versions( IdentifierType::SITE, $host ),
			),
			$this->keys->hash_identifier( IdentifierType::SITE, $host )
		);
	}

	private function schedule(): void {
		if ( ! function_exists( 'as_schedule_single_action' ) ) {
			return;
		}
		$bucket = (string) ( time() - ( time() % 60 ) );
		$args   = array( $bucket );
		if ( function_exists( 'as_has_scheduled_action' ) && as_has_scheduled_action( self::HOOK, $args, EmergencyMode::GROUP ) ) {
			return;
		}
		as_schedule_single_action( time() + 15, self::HOOK, $args, EmergencyMode::GROUP, true );
	}
}
