<?php
/**
 * Request-local, behavior-neutral velocity observations for extensions.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

final class VelocityObservationState {
	/**
	 * Existing Free velocity results keyed by identity type.
	 *
	 * @var array<int,array{effective:int,free_threshold:int,window:int,trusted:bool,free_crossed:bool}>
	 */
	private array $observations = array();

	public function record( int $identity_type, int $effective, int $free_threshold, int $window, bool $trusted ): void {
		$this->observations[ $identity_type ] = array(
			'effective'      => max( 0, $effective ),
			'free_threshold' => max( 1, $free_threshold ),
			'window'         => max( 1, $window ),
			'trusted'        => $trusted,
			'free_crossed'   => $effective >= $free_threshold,
		);
	}

	/**
	 * Return the request-local observations.
	 *
	 * @return array<int,array{effective:int,free_threshold:int,window:int,trusted:bool,free_crossed:bool}>
	 */
	public function all(): array {
		return $this->observations;
	}

	public function crossed_free_threshold(): bool {
		foreach ( $this->observations as $observation ) {
			if ( $observation['free_crossed'] ) {
				return true;
			}
		}
		return false;
	}
}
