<?php
/**
 * Explicit destructive uninstall behavior.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Lifecycle;

use Codeprint\CheckoutFirewall\Database\TableNames;
use Codeprint\CheckoutFirewall\Protection\PaymentAttemptCleaner;
use Codeprint\CheckoutFirewall\Scheduler\CleanupScheduler;

final class Uninstaller {
	private const OPTIONS = array(
		'cwf_db_version',
		'cwf_plugin_version',
		'cwf_hmac_keys',
		'cwf_delete_data_on_uninstall',
		'cwf_migration_lock',
		'cwf_schedules_version',
		'cwf_health_state',
		'cwf_turnstile_site_key',
		'cwf_turnstile_secret_key',
		'cwf_turnstile_enabled',
		'cwf_turnstile_verification',
		'cwf_challenge_provider',
		'cwf_challenge_provider_recovery',
		'cwf_recaptcha_site_key',
		'cwf_recaptcha_secret_key',
		'cwf_recaptcha_enabled',
		'cwf_recaptcha_verification',
		'cwf_emergency_mode',
		'cwf_operating_mode',
		'cwf_trusted_exemptions',
		'cwf_free_incident_state',
		'cwf_attack_email_enabled',
		'cwf_attack_email_recipient',
		'cwf_attack_email_state',
		'cwf_event_retention_days',
		'cwf_block_history_retention_days',
		'cwf_block_hint_retention_days',
		'cwf_admin_health_snapshot',
		'cwf_proxy_mode',
		'cwf_proxy_header',
		'cwf_trusted_proxy_cidrs',
		'cwf_pro_attack_state',
		'cwf_pro_attack_audit',
		'cwf_pro_automation_pause',
		'cwf_pro_rotation_state',
		'cwf_pro_incident_ledger',
		'cwf_pro_alert_destinations',
		'cwf_pro_alert_state',
	);

	public static function run(): void {
		if ( is_multisite() || ! self::purge_is_authorized() ) {
			return;
		}

		CleanupScheduler::unschedule();
		if ( function_exists( 'as_unschedule_all_actions' ) ) {
			as_unschedule_all_actions( 'checkout_firewall_pro_alert_delivery', array(), 'checkout-firewall-pro-alerts' );
			as_unschedule_all_actions( 'checkout_firewall_evaluate_free_incident', array(), 'checkout-firewall' );
			as_unschedule_all_actions( 'checkout_firewall_send_free_incident_email', array(), 'checkout-firewall' );
		}
		( new PaymentAttemptCleaner() )->purge_all();
		self::drop_tables();

		$options = self::OPTIONS;
		$class   = 'Codeprint\\CheckoutFirewall\\Premium\\BuildSentinel';
		if ( class_exists( $class ) ) {
			$options = array_merge( $options, $class::uninstall_options() );
		}
		foreach ( $options as $option ) {
			delete_option( $option );
		}
	}

	public static function purge_is_authorized(): bool {
		if ( defined( 'CWF_DELETE_DATA_ON_UNINSTALL' ) && true === CWF_DELETE_DATA_ON_UNINSTALL ) {
			return true;
		}

		$value = get_option( 'cwf_delete_data_on_uninstall', false );
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
