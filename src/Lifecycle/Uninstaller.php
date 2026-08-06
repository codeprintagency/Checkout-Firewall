<?php
/**
 * Explicit destructive uninstall behavior.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Lifecycle;

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- Explicit purge targets only the closed, prefix-validated TableNames registry after administrator-authorized uninstall.

use Codeprint\CheckoutFirewall\Database\TableNames;
use Codeprint\CheckoutFirewall\Protection\PaymentAttemptCleaner;
use Codeprint\CheckoutFirewall\Scheduler\CleanupScheduler;

final class Uninstaller {
	private const OPTIONS = array(
		'checkout_firewall_db_version',
		'checkout_firewall_plugin_version',
		'checkout_firewall_hmac_keys',
		'checkout_firewall_delete_data_on_uninstall',
		'checkout_firewall_migration_lock',
		'checkout_firewall_schedules_version',
		'checkout_firewall_health_state',
		'checkout_firewall_turnstile_site_key',
		'checkout_firewall_turnstile_secret_key',
		'checkout_firewall_turnstile_enabled',
		'checkout_firewall_turnstile_verification',
		'checkout_firewall_challenge_provider',
		'checkout_firewall_challenge_provider_recovery',
		'checkout_firewall_recaptcha_site_key',
		'checkout_firewall_recaptcha_secret_key',
		'checkout_firewall_recaptcha_enabled',
		'checkout_firewall_recaptcha_verification',
		'checkout_firewall_emergency_mode',
		'checkout_firewall_operating_mode',
		'checkout_firewall_trusted_exemptions',
		'checkout_firewall_free_incident_state',
		'checkout_firewall_attack_email_enabled',
		'checkout_firewall_attack_email_recipient',
		'checkout_firewall_attack_email_state',
		'checkout_firewall_event_retention_days',
		'checkout_firewall_block_history_retention_days',
		'checkout_firewall_block_hint_retention_days',
		'checkout_firewall_admin_health_snapshot',
		'checkout_firewall_proxy_mode',
		'checkout_firewall_proxy_header',
		'checkout_firewall_trusted_proxy_cidrs',
	);

	public static function run(): void {
		if ( is_multisite() || ! self::purge_is_authorized() ) {
			return;
		}

		CleanupScheduler::unschedule();
		if ( function_exists( 'as_unschedule_all_actions' ) ) {
			as_unschedule_all_actions( 'checkout_firewall_evaluate_free_incident', array(), 'checkout-firewall' );
			as_unschedule_all_actions( 'checkout_firewall_send_free_incident_email', array(), 'checkout-firewall' );
		}
		( new PaymentAttemptCleaner() )->purge_all();
		self::drop_tables();

		foreach ( self::OPTIONS as $option ) {
			delete_option( $option );
		}
	}

	public static function purge_is_authorized(): bool {
		if ( defined( 'CHECKOUT_FIREWALL_DELETE_DATA_ON_UNINSTALL' ) && true === CHECKOUT_FIREWALL_DELETE_DATA_ON_UNINSTALL ) {
			return true;
		}

		$value = get_option( 'checkout_firewall_delete_data_on_uninstall', false );
		return true === $value || '1' === $value || 1 === $value;
	}

	/**
	 * Resolve the exact tables eligible for explicit purge.
	 *
	 * @return list<string>
	 */
	public static function target_tables(): array {
		return array_values( TableNames::from_wordpress()->all() );
	}

	private static function drop_tables(): void {
		global $wpdb;

		foreach ( self::target_tables() as $table ) {
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			if ( $table !== $found ) {
				continue;
			}

			$wpdb->query( "DROP TABLE `{$table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.SchemaChange
		}
	}
}
