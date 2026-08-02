<?php
/**
 * Explicit Standard/Observe operating-mode state.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

final class OperatingMode {
	public const OPTION         = 'cwf_operating_mode';
	public const OBSERVE        = 'observe';
	public const STANDARD       = 'standard';
	public const REVIEW_SECONDS = 7 * DAY_IN_SECONDS;

	/**
	 * Clock used for deterministic state transitions.
	 *
	 * @var \Closure():int
	 */
	private \Closure $clock;
	/**
	 * Random-byte source used for transition identifiers.
	 *
	 * @var \Closure(int):string
	 */
	private \Closure $random;

	public function __construct( ?callable $clock = null, ?callable $random = null ) {
		$this->clock  = \Closure::fromCallable( $clock ?? 'time' );
		$this->random = \Closure::fromCallable( $random ?? 'random_bytes' );
	}

	/** Initialize only a genuinely new installation. */
	public function initialize_fresh(): void {
		if ( false === get_option( self::OPTION, false ) ) {
			$this->write( self::OBSERVE );
		}
	}

	public function current(): string {
		$state = $this->state();
		return null === $state ? self::STANDARD : (string) $state['mode'];
	}

	public function is_observing(): bool {
		return self::OBSERVE === $this->current();
	}

	public function is_standard(): bool {
		return self::STANDARD === $this->current();
	}

	/**
	 * Return the validated persisted state.
	 *
	 * @return array<string,mixed>|null
	 */
	public function state(): ?array {
		$value = get_option( self::OPTION, false );
		if ( ! is_array( $value ) || 1 !== ( $value['format'] ?? null )
			|| ! in_array( $value['mode'] ?? null, array( self::OBSERVE, self::STANDARD ), true )
			|| ! self::valid_date( $value['started_at_gmt'] ?? null )
			|| ! self::valid_date( $value['review_after_gmt'] ?? null )
			|| ! self::valid_date( $value['enforcement_epoch_gmt'] ?? null )
			|| ! is_string( $value['transition_id'] ?? null )
			|| 1 !== preg_match( '/^[a-f0-9]{32}$/D', $value['transition_id'] )
		) {
			return null;
		}
		return $value;
	}

	/**
	 * Explicitly enter Observe Mode.
	 *
	 * @return array<string,mixed>
	 */
	public function enter_observe(): array {
		return $this->write( self::OBSERVE );
	}

	/**
	 * Explicitly enter Standard Mode with a fresh enforcement epoch.
	 *
	 * @return array<string,mixed>
	 */
	public function enter_standard(): array {
		return $this->write( self::STANDARD );
	}

	public function enforcement_epoch(): string {
		$state = $this->state();
		return null !== $state && self::STANDARD === $state['mode']
			? (string) $state['enforcement_epoch_gmt']
			: '1970-01-01 00:00:00';
	}

	/**
	 * Persist a complete operating-mode transition.
	 *
	 * @return array<string,mixed>
	 * @throws \RuntimeException When secure state cannot be created or saved.
	 */
	private function write( string $mode ): array {
		$now    = ( $this->clock )();
		$random = ( $this->random )( 16 );
		if ( 16 !== strlen( $random ) ) {
			throw new \RuntimeException( 'Operating-mode random source is invalid.' );
		}
		$state = array(
			'format'                => 1,
			'mode'                  => $mode,
			'started_at_gmt'        => gmdate( 'Y-m-d H:i:s', $now ),
			'review_after_gmt'      => gmdate( 'Y-m-d H:i:s', self::OBSERVE === $mode ? $now + self::REVIEW_SECONDS : $now ),
			'enforcement_epoch_gmt' => gmdate( 'Y-m-d H:i:s', self::STANDARD === $mode ? $now : 0 ),
			'transition_id'         => bin2hex( $random ),
		);
		if ( false === get_option( self::OPTION, false ) ) {
			if ( ! add_option( self::OPTION, $state, '', false ) ) {
				throw new \RuntimeException( 'Operating mode could not be created.' );
			}
		} elseif ( ! update_option( self::OPTION, $state, false ) && get_option( self::OPTION, false ) !== $state ) {
			throw new \RuntimeException( 'Operating mode could not be saved.' );
		}
		return $state;
	}

	private static function valid_date( mixed $value ): bool {
		return is_string( $value ) && 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $value ) && false !== strtotime( $value . ' UTC' );
	}
}
