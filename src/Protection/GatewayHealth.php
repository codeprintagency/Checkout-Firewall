<?php
/**
 * Basic gateway outcome safety window.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Data\CounterType;

final class GatewayHealth {
	private CounterRepository $counters;
	private IdentityRegistry $identities;
	private ?GatewayObservationState $observations;

	public function __construct( CounterRepository $counters, IdentityRegistry $identities, ?GatewayObservationState $observations = null ) {
		$this->counters     = $counters;
		$this->identities   = $identities;
		$this->observations = $observations;
	}

	public function record( int $counter_type, string $gateway, ?int $now = null ): void {
		$identity = $this->identities->gateway( $gateway );
		$this->counters->increment( array( $identity['identifier_type'] => $identity ), $counter_type, $gateway, $now );
	}

	public function is_outage( string $gateway, ?int $now = null ): bool {
		if ( '' === $gateway ) {
			return false;
		}
		return $this->snapshot( $gateway, $now )['outage'];
	}

	/**
	 * Return the exact gateway values already required by M4 outage safety.
	 *
	 * @return array{success:int,decline:int,other:int,outage:bool}
	 */
	public function snapshot( string $gateway, ?int $now = null ): array {
		$identity   = $this->identities->gateway( $gateway );
		$identities = array( $identity['identifier_type'] => $identity );
		$success    = $this->value( $identities, CounterType::PAYMENT_SUCCESS, $gateway, $now );
		$decline    = $this->value( $identities, CounterType::GATEWAY_DECLINE, $gateway, $now );
		$other      = $this->value( $identities, CounterType::OTHER_FAILURE, $gateway, $now );
		$snapshot   = array(
			'success' => $success,
			'decline' => $decline,
			'other'   => $other,
			'outage'  => ProtectionPolicy::outage( $success, $decline, $other ),
		);
		if ( null !== $this->observations ) {
			$this->observations->record( $gateway, $snapshot );
		}
		return $snapshot;
	}

	public function source( string $gateway ): string {
		$identity = $this->identities->gateway( $gateway );
		return 'failure_' . substr( bin2hex( (string) $identity['identifier_hash'] ), 0, 16 );
	}

	/**
	 * Read one gateway health counter.
	 *
	 * @param array<int,array<string,mixed>> $identities Gateway identity.
	 */
	private function value( array $identities, int $type, string $gateway, ?int $now ): int {
		$values = $this->counters->totals( $identities, $type, ProtectionPolicy::OUTAGE_WINDOW, $gateway, $now );
		return (int) reset( $values );
	}
}
