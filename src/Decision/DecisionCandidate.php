<?php
/**
 * A bounded candidate submitted to the central decision engine.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Decision;

final class DecisionCandidate {
	private const MAX_SIGNAL_COUNT = 8;
	private const MAX_SIGNAL_BYTES = 512;

	private string $action;
	private string $reason;

	/**
	 * Bounded safe signals.
	 *
	 * @var array<string,string|int|float|bool|null>
	 */
	private array $signals;

	/**
	 * Create a typed, bounded decision candidate.
	 *
	 * @param array<mixed,mixed> $signals Safe scalar diagnostic signals.
	 * @throws \InvalidArgumentException When the action, reason, or signals are invalid.
	 */
	public function __construct( string $action, string $reason, array $signals = array() ) {
		if ( ! in_array( $action, DecisionAction::all(), true ) || ! ReasonCatalog::has( $reason ) ) {
			throw new \InvalidArgumentException( 'Invalid checkout decision candidate.' );
		}
		if ( ReasonCatalog::action( $reason ) !== $action ) {
			throw new \InvalidArgumentException( 'Decision action is incompatible with its reason.' );
		}

		$this->action  = $action;
		$this->reason  = $reason;
		$this->signals = self::normalize_signals( $signals );
	}

	public function action(): string {
		return $this->action;
	}

	public function reason(): string {
		return $this->reason;
	}

	/**
	 * Return bounded safe signals.
	 *
	 * @return array<string,string|int|float|bool|null>
	 */
	public function signals(): array {
		return $this->signals;
	}

	/**
	 * Normalize and validate candidate signals.
	 *
	 * @param array<mixed,mixed> $signals Raw signals.
	 * @return array<string,string|int|float|bool|null>
	 * @throws \InvalidArgumentException When any signal exceeds the approved boundary.
	 */
	private static function normalize_signals( array $signals ): array {
		if ( count( $signals ) > self::MAX_SIGNAL_COUNT ) {
			throw new \InvalidArgumentException( 'Too many checkout decision signals.' );
		}

		$normalized = array();
		foreach ( $signals as $key => $value ) {
			if ( ! is_string( $key ) || 1 !== preg_match( '/^[a-z][a-z0-9_]{0,31}$/D', $key ) || ( ! is_scalar( $value ) && null !== $value ) ) {
				throw new \InvalidArgumentException( 'Invalid checkout decision signal.' );
			}
			if ( is_string( $value ) ) {
				$value = substr( $value, 0, 64 );
			}
			$normalized[ $key ] = $value;
		}

		$encoded = wp_json_encode( $normalized );
		if ( ! is_string( $encoded ) || strlen( $encoded ) > self::MAX_SIGNAL_BYTES ) {
			throw new \InvalidArgumentException( 'Checkout decision signals exceed their byte limit.' );
		}

		return $normalized;
	}
}
