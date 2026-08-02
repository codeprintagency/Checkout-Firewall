<?php
/**
 * Action Scheduler retention orchestration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Scheduler;

use Codeprint\CheckoutFirewall\Database\Cleaner;
use Codeprint\CheckoutFirewall\Database\Migrator;
use Codeprint\CheckoutFirewall\Protection\PaymentAttemptCleaner;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class CleanupScheduler {
	public const GROUP          = 'checkout-firewall';
	public const VERSION_OPTION = 'cwf_schedules_version';
	public const VERSION        = 1;

	private const HEALTH_INTERVAL = 86400;
	private const MAX_CHAIN       = 100;

	private const ACTIONS = array(
		'checkout_firewall_cleanup_events'          => DAY_IN_SECONDS,
		'checkout_firewall_cleanup_counters'        => 300,
		'checkout_firewall_cleanup_blocks'          => DAY_IN_SECONDS,
		'checkout_firewall_cleanup_consumed_tokens' => 300,
	);

	public static function register(): void {
		add_action( 'action_scheduler_init', array( self::class, 'maybe_ensure_schedules' ) );
		add_action( 'checkout_firewall_cleanup_events', array( self::class, 'cleanup_events' ), 10, 1 );
		add_action( 'checkout_firewall_cleanup_counters', array( self::class, 'cleanup_counters' ), 10, 1 );
		add_action( 'checkout_firewall_cleanup_blocks', array( self::class, 'cleanup_blocks' ), 10, 1 );
		add_action( 'checkout_firewall_cleanup_consumed_tokens', array( self::class, 'cleanup_consumed_tokens' ), 10, 1 );
	}

	public static function maybe_ensure_schedules(): void {
		$installed = (int) get_option( self::VERSION_OPTION, 0 );
		if ( self::VERSION === $installed ) {
			if ( ! self::is_maintenance_context() || time() - Health::timestamp( 'schedule_checked_at' ) < self::HEALTH_INTERVAL ) {
				return;
			}
		}

		self::ensure_schedules();
	}

	public static function ensure_schedules(): bool {
		if ( ! function_exists( 'as_has_scheduled_action' ) || ! function_exists( 'as_schedule_recurring_action' ) ) {
			Health::record( 'scheduler', 'api_unavailable' );
			return false;
		}

		$recreated = false;
		foreach ( self::ACTIONS as $hook => $interval ) {
			if ( as_has_scheduled_action( $hook, array(), self::GROUP ) ) {
				continue;
			}

			$action_id = as_schedule_recurring_action( time() + 60, $interval, $hook, array(), self::GROUP, true );
			if ( 0 === (int) $action_id ) {
				Health::record( 'scheduler', 'schedule_failed' );
				return false;
			}
			$recreated = true;
		}

		Migrator::write_option( self::VERSION_OPTION, self::VERSION );
		Health::set_timestamp( 'schedule_checked_at', time() );
		Health::record( 'scheduler', $recreated ? 'schedule_recreated' : 'healthy' );
		return true;
	}

	public static function unschedule(): void {
		if ( function_exists( 'as_unschedule_all_actions' ) ) {
			as_unschedule_all_actions( '', array(), self::GROUP );
		}

		delete_option( self::VERSION_OPTION );
	}

	public static function cleanup_events( int $chain = 0 ): void {
		self::run( 'events', $chain );
	}

	public static function cleanup_counters( int $chain = 0 ): void {
		self::run( 'counters', $chain );
	}

	public static function cleanup_blocks( int $chain = 0 ): void {
		self::run( 'blocks', $chain );
	}

	public static function cleanup_consumed_tokens( int $chain = 0 ): void {
		self::run( 'consumed_tokens', $chain );
	}

	private static function run( string $kind, int $chain ): void {
		try {
			$cleaner = new Cleaner();
			$backlog = $cleaner->{$kind}();
			if ( 'events' === $kind ) {
				$backlog = ( new PaymentAttemptCleaner() )->expired() || $backlog;
			}
			if ( ! $backlog ) {
				Health::clear( 'cleanup_' . $kind );
				return;
			}

			if ( $chain >= self::MAX_CHAIN ) {
				Health::record( 'cleanup_' . $kind, 'falling_behind' );
				return;
			}

			self::schedule_follow_up( $kind, $chain + 1, 1 );
		} catch ( \Throwable $exception ) {
			Health::record( 'cleanup_' . $kind, 'failed' );
			SafeLogger::exception( 'cleanup_' . $kind . '_failed', $exception );
			self::schedule_follow_up( $kind, 0, 60 );
		}
	}

	private static function schedule_follow_up( string $kind, int $chain, int $delay ): void {
		if ( ! function_exists( 'as_schedule_single_action' ) ) {
			Health::record( 'cleanup_' . $kind, 'retry_api_unavailable' );
			return;
		}

		$hook      = 'checkout_firewall_cleanup_' . $kind;
		$action_id = as_schedule_single_action( time() + $delay, $hook, array( $chain ), self::GROUP, true );
		if ( 0 === (int) $action_id ) {
			Health::record( 'cleanup_' . $kind, 'retry_schedule_failed' );
		}
	}

	private static function is_maintenance_context(): bool {
		return is_admin()
			|| ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() )
			|| ( defined( 'WP_CLI' ) && WP_CLI );
	}
}
