<?php
/**
 * Manual, timestamp-authoritative Emergency Mode.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Support\SafeLogger;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConflictDetector;

final class EmergencyMode {
	public const OPTION      = 'checkout_firewall_emergency_mode';
	public const EXPIRE_HOOK = 'checkout_firewall_expire_emergency';
	public const GROUP       = 'checkout-firewall';
	public const DURATIONS   = array( 3600, 14400, 43200, 86400 );

	private TurnstileConfig $turnstile;
	private TurnstileConflictDetector $conflicts;
	private ?ChallengeConfig $challenges;
	private OperatingMode $operating;
	/** Current UTC timestamp provider. @var \Closure():int */
	private \Closure $clock;
	/** Secure random-byte provider. @var \Closure(int):string */
	private \Closure $random;

	public function __construct( ?TurnstileConfig $turnstile = null, ?TurnstileConflictDetector $conflicts = null, ?callable $clock = null, ?callable $random = null, ?ChallengeConfig $challenges = null, ?OperatingMode $operating = null ) {
		$this->turnstile  = $turnstile ?? new TurnstileConfig();
		$this->conflicts  = $conflicts ?? new TurnstileConflictDetector();
		$this->clock      = \Closure::fromCallable( $clock ?? 'time' );
		$this->random     = \Closure::fromCallable( $random ?? 'random_bytes' );
		$this->challenges = $challenges;
		$this->operating  = $operating ?? new OperatingMode();
	}

	public function register(): void {
		add_action( 'action_scheduler_init', array( $this, 'reconcile' ) );
		add_action( self::EXPIRE_HOOK, array( $this, 'expire' ), 10, 2 );
	}

	/**
	 * Read one structurally valid Emergency state.
	 *
	 * @return array<string,mixed>|null
	 */
	public function state(): ?array {
		$value = get_option( self::OPTION, false );
		if ( ! is_array( $value ) || 1 !== ( $value['format'] ?? null ) || 'emergency' !== ( $value['mode'] ?? null )
			|| ! is_string( $value['activation_id'] ?? null ) || 1 !== preg_match( '/^[a-f0-9]{32}$/D', $value['activation_id'] )
			|| ! self::valid_date( $value['started_at_gmt'] ?? null ) || ! self::valid_date( $value['expires_at_gmt'] ?? null )
			|| strtotime( (string) $value['expires_at_gmt'] . ' UTC' ) <= strtotime( (string) $value['started_at_gmt'] . ' UTC' )
		) {
			return null;
		}
		return $value;
	}

	public function is_active(): bool {
		$state = $this->state();
		return null !== $state && strtotime( (string) $state['expires_at_gmt'] . ' UTC' ) > ( $this->clock )();
	}

	/**
	 * Start a new time-boxed activation or return the live activation.
	 *
	 * @return array<string,mixed>
	 * @throws \InvalidArgumentException For an unsupported duration.
	 * @throws \RuntimeException When activation preconditions or randomness fail.
	 */
	public function start( int $seconds ): array {
		if ( ! $this->operating->is_standard() ) {
			throw new \RuntimeException( 'Emergency Mode is unavailable during Observe Mode.' );
		}
		if ( ! in_array( $seconds, self::DURATIONS, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported Emergency Mode duration.' );
		}
		$existing = $this->state();
		if ( $this->is_active() && null !== $existing ) {
			return $existing;
		}
		if ( ! $this->recovery_available() ) {
			throw new \RuntimeException( 'Emergency Mode requires an available checkout challenge provider.' );
		}
		$now    = ( $this->clock )();
		$random = ( $this->random )( 16 );
		if ( 16 !== strlen( $random ) ) {
			throw new \RuntimeException( 'Emergency Mode random source is invalid.' );
		}
		$state = array(
			'format'         => 1,
			'mode'           => 'emergency',
			'activation_id'  => bin2hex( $random ),
			'started_at_gmt' => gmdate( 'Y-m-d H:i:s', $now ),
			'expires_at_gmt' => gmdate( 'Y-m-d H:i:s', $now + $seconds ),
		);
		self::write( $state );
		Health::clear( 'emergency' );
		$this->schedule( $state );
		return $state;
	}

	public function recovery_available(): bool {
		return null !== $this->challenges
			? $this->challenges->is_available()
			: $this->turnstile->is_active() && ! $this->conflicts->has_conflict();
	}

	public function stop(): void {
		$state = $this->state();
		delete_option( self::OPTION );
		Health::clear( 'emergency' );
		if ( null !== $state && function_exists( 'as_unschedule_all_actions' ) ) {
			try {
				as_unschedule_all_actions( self::EXPIRE_HOOK, array( (string) $state['activation_id'], (string) $state['expires_at_gmt'] ), self::GROUP );
			} catch ( \Throwable $exception ) {
				SafeLogger::exception( 'emergency_unschedule_failed', $exception );
			}
		}
	}

	public function expire( string $activation_id, string $expires_at_gmt ): void {
		$state = $this->state();
		if ( null !== $state && hash_equals( (string) $state['activation_id'], $activation_id )
			&& hash_equals( (string) $state['expires_at_gmt'], $expires_at_gmt )
			&& strtotime( $expires_at_gmt . ' UTC' ) <= ( $this->clock )()
		) {
			delete_option( self::OPTION );
			Health::clear( 'emergency' );
		}
	}

	public function reconcile(): void {
		$state = $this->state();
		if ( null === $state ) {
			if ( false !== get_option( self::OPTION, false ) ) {
				delete_option( self::OPTION );
				Health::record( 'emergency', 'invalid_state' );
			}
			return;
		}
		if ( ! $this->is_active() ) {
			delete_option( self::OPTION );
			Health::clear( 'emergency' );
			return;
		}
		$this->schedule( $state );
	}

	/**
	 * Reconcile the unique expiry action for one live activation.
	 *
	 * @param array<string,mixed> $state Emergency activation state.
	 */
	private function schedule( array $state ): void {
		if ( ! function_exists( 'as_has_scheduled_action' ) || ! function_exists( 'as_schedule_single_action' ) ) {
			Health::record( 'emergency', 'expiry_schedule_unavailable' );
			return;
		}
		$args = array( (string) $state['activation_id'], (string) $state['expires_at_gmt'] );
		if ( ! as_has_scheduled_action( self::EXPIRE_HOOK, $args, self::GROUP ) ) {
			$id = as_schedule_single_action( strtotime( (string) $state['expires_at_gmt'] . ' UTC' ), self::EXPIRE_HOOK, $args, self::GROUP, true );
			if ( 0 === (int) $id ) {
				Health::record( 'emergency', 'expiry_schedule_failed' );
			}
		}
	}

	/**
	 * Validate one closed UTC database timestamp.
	 *
	 * @param mixed $value Candidate timestamp.
	 */
	private static function valid_date( $value ): bool {
		return is_string( $value ) && 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $value ) && false !== strtotime( $value . ' UTC' );
	}

	/**
	 * Persist the non-autoloaded Emergency record.
	 *
	 * @param array<string,mixed> $state Emergency activation state.
	 */
	private static function write( array $state ): void {
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, $state, '', false );
			return;
		}
		update_option( self::OPTION, $state, false );
	}
}
