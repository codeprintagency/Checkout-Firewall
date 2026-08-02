<?php
/**
 * Disabled-until-Premium request-local gateway outcome snapshots.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

final class GatewayObservationState {
	private bool $enabled = false;
	/**
	 * Sanitized gateway snapshots.
	 *
	 * @var array<string,array{success:int,decline:int,other:int,outage:bool}>
	 */
	private array $snapshots = array();
	/**
	 * Bounded read-only listeners.
	 *
	 * @var list<callable(string,array<string,mixed>):void>
	 */
	private array $listeners = array();

	public function enable(): void {
		$this->enabled = true;
	}

	/** Register one bounded read-only observation listener. */
	public function listen( callable $listener ): bool {
		if ( count( $this->listeners ) >= 1 ) {
			return false;
		}
		$this->listeners[] = $listener;
		return true;
	}

	/**
	 * Record a snapshot only after Premium enables the seam.
	 *
	 * @param array{success:int,decline:int,other:int,outage:bool} $snapshot Gateway totals.
	 */
	public function record( string $gateway, array $snapshot ): void {
		if ( ! $this->enabled || array( 'success', 'decline', 'other', 'outage' ) !== array_keys( $snapshot )
			|| ! is_int( $snapshot['success'] ) || $snapshot['success'] < 0
			|| ! is_int( $snapshot['decline'] ) || $snapshot['decline'] < 0
			|| ! is_int( $snapshot['other'] ) || $snapshot['other'] < 0
			|| ! is_bool( $snapshot['outage'] )
		) {
			return;
		}
		$gateway = substr( sanitize_key( $gateway ), 0, 64 );
		if ( '' !== $gateway ) {
			$this->snapshots[ $gateway ] = $snapshot;
			foreach ( $this->listeners as $listener ) {
				try {
					$listener( $gateway, $snapshot );
				} catch ( \Throwable $exception ) {
					unset( $exception );
				}
			}
		}
	}

	/**
	 * Read one request-local gateway snapshot.
	 *
	 * @return array{success:int,decline:int,other:int,outage:bool}|null
	 */
	public function read( string $gateway ): ?array {
		$gateway = substr( sanitize_key( $gateway ), 0, 64 );
		return $this->enabled && '' !== $gateway ? ( $this->snapshots[ $gateway ] ?? null ) : null;
	}
}
