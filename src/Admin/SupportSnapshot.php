<?php
/**
 * Privacy-bounded support snapshot.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Commercial\CommercialBootstrap;
use Codeprint\CheckoutFirewall\Database\Schema;
use Codeprint\CheckoutFirewall\Database\TableNames;
use Codeprint\CheckoutFirewall\Lifecycle\Uninstaller;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;
use Codeprint\CheckoutFirewall\Operations\FreeIncidentState;
use Codeprint\CheckoutFirewall\Protection\TrustedExemptionStore;
use Codeprint\CheckoutFirewall\Operations\RetentionPolicy;
use Codeprint\CheckoutFirewall\Protection\ClientIpResolver;
use Codeprint\CheckoutFirewall\Recaptcha\RecaptchaConfig;
use Codeprint\CheckoutFirewall\Scheduler\CleanupScheduler;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;

final class SupportSnapshot {
	public const FORMAT = 1;

	private const SCHEDULES = array(
		'checkout_firewall_cleanup_events',
		'checkout_firewall_cleanup_counters',
		'checkout_firewall_cleanup_blocks',
		'checkout_firewall_cleanup_consumed_tokens',
	);

	private const HEALTH_COMPONENTS = array(
		'requirements',
		'schema',
		'key',
		'scheduler',
		'emergency',
		'mail',
		'turnstile',
		'cleanup_events',
		'cleanup_counters',
		'cleanup_blocks',
		'cleanup_consumed_tokens',
	);

	private const HEALTH_CODES = array(
		'healthy',
		'schedule_recreated',
		'api_unavailable',
		'schedule_failed',
		'verification_failed',
		'dbdelta_failed',
		'migration_exception',
		'migration_lock_lost',
		'migration_locked',
		'invalid_state',
		'prerequisite_unavailable',
		'expiry_schedule_failed',
		'expiry_schedule_unavailable',
		'queue_failed',
		'recipient_invalid',
		'retry_schedule_failed',
		'schedule_unavailable',
		'send_failed',
		'invalid_secret',
		'failed',
		'falling_behind',
		'retry_api_unavailable',
		'runtime_unavailable',
		'woocommerce_missing',
		'wordpress_version',
		'php_version',
		'unknown',
	);

	/**
	 * Build the closed support snapshot.
	 *
	 * @return array<string,mixed>
	 */
	public function build(): array {
		$turnstile        = new TurnstileConfig();
		$credentials      = $turnstile->credentials();
		$recaptcha        = new RecaptchaConfig();
		$recaptcha_keys   = $recaptcha->credentials();
		$challenges       = new ChallengeConfig( $turnstile, $recaptcha );
		$provider         = CommercialBootstrap::provider();
		$entitlement      = $provider->entitlement();
		$code_type        = CommercialBootstrap::config()->code_type();
		$proxy_mode       = ( new ClientIpResolver() )->configured_mode();
		$emergency_active = ( new EmergencyMode() )->is_active();
		$operating        = new OperatingMode();
		$operating_state  = $operating->state();
		$exemptions       = ( new TrustedExemptionStore() )->active();
		$incident         = ( new FreeIncidentState() )->read();
		$exemption_counts = array(
			'ip'      => 0,
			'network' => 0,
			'user'    => 0,
		);
		foreach ( $exemptions as $exemption ) {
			$type = (string) ( $exemption['subject_type'] ?? '' );
			if ( isset( $exemption_counts[ $type ] ) ) {
				++$exemption_counts[ $type ];
			}
		}

		return array(
			'format'           => self::FORMAT,
			'generated_at_gmt' => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'plugin'           => array(
				'version'        => defined( 'CWF_VERSION' ) ? (string) CWF_VERSION : 'unknown',
				'code_type'      => in_array( $code_type, array( 'free', 'premium' ), true ) ? $code_type : 'free',
				'schema_version' => Schema::VERSION,
			),
			'environment'      => $this->environment(),
			'compatibility'    => array(
				'hpos'                 => true,
				'cart_checkout_blocks' => true,
				'multisite_supported'  => false,
			),
			'configuration'    => array(
				'mode'                  => $emergency_active ? 'emergency' : $operating->current(),
				'mode_review_at_gmt'    => null === $operating_state ? '' : (string) $operating_state['review_after_gmt'],
				'enforcement_epoch_gmt' => null === $operating_state ? '' : (string) $operating_state['enforcement_epoch_gmt'],
				'emergency_active'      => $emergency_active,
				'trusted_exemptions'    => min( 100, count( $exemptions ) ),
				'trusted_by_type'       => $exemption_counts,
				'free_incident_active'  => null !== $incident && 'open' === ( $incident['status'] ?? null ),
				'free_incident_status'  => null === $incident ? 'none' : (string) $incident['status'],
				'turnstile_configured'  => '' !== $credentials['site_key'] && '' !== $credentials['secret_key'],
				'turnstile_verified'    => $turnstile->is_active(),
				'challenge_selected'    => $challenges->selected(),
				'challenge_effective'   => $challenges->effective(),
				'recaptcha_configured'  => '' !== $recaptcha_keys['site_key'] && '' !== $recaptcha_keys['secret_key'],
				'recaptcha_verified'    => $recaptcha->is_active(),
				'proxy_mode'            => in_array( $proxy_mode, array( ClientIpResolver::MODE_AUTOMATIC, ClientIpResolver::MODE_MANUAL ), true ) ? $proxy_mode : 'invalid',
				'event_retention_days'  => (int) ( RetentionPolicy::event_seconds() / DAY_IN_SECONDS ),
				'hint_retention_days'   => (int) ( RetentionPolicy::hint_seconds() / DAY_IN_SECONDS ),
				'uninstall_policy'      => Uninstaller::purge_is_authorized() ? 'delete' : 'preserve',
			),
			'health'           => $this->health(),
			'schedules'        => $this->schedules(),
			'storage'          => $this->storage(),
			'commercial'       => array(
				'configured'        => CommercialBootstrap::config()->is_configured(),
				'connected'         => $this->connected(),
				'entitlement_state' => in_array( $entitlement->state(), array( 'free', 'active_paid', 'expired', 'cancelled', 'invalid', 'missing', 'unconfigured', 'provider_error' ), true ) ? $entitlement->state() : 'provider_error',
			),
		);
	}

	/**
	 * Return bounded software environment versions.
	 *
	 * @return array<string,string>
	 */
	private function environment(): array {
		global $wpdb;
		$database_version = method_exists( $wpdb, 'db_version' ) ? (string) $wpdb->db_version() : 'unknown';
		$database_version = 1 === preg_match( '/^[0-9A-Za-z.+_-]{1,32}$/D', $database_version ) ? $database_version : 'unknown';
		$server_info      = method_exists( $wpdb, 'db_server_info' ) ? (string) $wpdb->db_server_info() : '';
		$database_family  = 'unknown' === $database_version ? 'unknown' : ( false !== stripos( $server_info, 'maria' ) ? 'mariadb' : 'mysql' );

		return array(
			'php_version'         => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION . '.' . PHP_RELEASE_VERSION,
			'wordpress_version'   => $this->version( $GLOBALS['wp_version'] ?? null, 'unknown' ),
			'woocommerce_version' => $this->version( defined( 'WC_VERSION' ) ? WC_VERSION : null, 'unavailable' ),
			'database_family'     => $database_family,
			'database_version'    => $database_version,
		);
	}

	/**
	 * Normalize a public software version.
	 *
	 * @param mixed  $value    Candidate version.
	 * @param string $fallback Closed fallback.
	 */
	private function version( $value, string $fallback ): string {
		return is_string( $value ) && 1 === preg_match( '/^[0-9A-Za-z.+_-]{1,32}$/D', $value ) ? $value : $fallback;
	}

	/**
	 * Return closed health components and values.
	 *
	 * @return array<string,array{status:string,code:string,observed_at_gmt:string}>
	 */
	private function health(): array {
		$stored = get_option( Health::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		$output = array();
		foreach ( self::HEALTH_COMPONENTS as $component ) {
			$row  = isset( $stored[ $component ] ) && is_array( $stored[ $component ] ) ? $stored[ $component ] : array();
			$code = isset( $row['code'] ) && is_string( $row['code'] ) && in_array( $row['code'], self::HEALTH_CODES, true ) ? $row['code'] : 'unknown';
			$time = isset( $row['updated_at_gmt'] ) && is_string( $row['updated_at_gmt'] ) && 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $row['updated_at_gmt'] ) ? $row['updated_at_gmt'] : '';

			$output[ $component ] = array(
				'status'          => in_array( $code, array( 'healthy', 'schedule_recreated' ), true ) ? 'healthy' : ( 'unknown' === $code ? 'unknown' : 'needs_attention' ),
				'code'            => $code,
				'observed_at_gmt' => $time,
			);
		}
		return $output;
	}

	/**
	 * Return exact cleanup-schedule presence.
	 *
	 * @return array<string,string>
	 */
	private function schedules(): array {
		$output = array();
		foreach ( self::SCHEDULES as $hook ) {
			$present = function_exists( 'as_has_scheduled_action' ) && as_has_scheduled_action( $hook, array(), CleanupScheduler::GROUP );

			$output[ $hook ] = $present ? 'present' : 'missing';
		}
		return $output;
	}

	/**
	 * Return bounded row-count buckets.
	 *
	 * @return array<string,string>
	 */
	private function storage(): array {
		global $wpdb;
		$output = array();
		foreach ( TableNames::from_wordpress()->all() as $logical => $table ) {
			$ids                = $wpdb->get_col( "SELECT id FROM `{$table}` ORDER BY id ASC LIMIT 1001" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table is resolved from the closed internal registry.
			$count              = is_array( $ids ) ? count( $ids ) : 0;
			$output[ $logical ] = 0 === $count ? 'empty' : ( $count <= 10 ? '1-10' : ( $count <= 100 ? '11-100' : ( $count <= 1000 ? '101-1000' : '1001+' ) ) );
		}
		return $output;
	}

	private function connected(): bool {
		$sdk = CommercialBootstrap::sdk();
		if ( null === $sdk || ! method_exists( $sdk, 'is_registered' ) ) {
			return false;
		}
		try {
			return (bool) $sdk->is_registered();
		} catch ( \Throwable $exception ) {
			unset( $exception );
			return false;
		}
	}
}
