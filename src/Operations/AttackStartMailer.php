<?php
/**
 * Privacy-safe Emergency Mode activation email.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class AttackStartMailer {
	public const ENABLED_OPTION   = 'checkout_firewall_attack_email_enabled';
	public const RECIPIENT_OPTION = 'checkout_firewall_attack_email_recipient';
	public const STATE_OPTION     = 'checkout_firewall_attack_email_state';
	public const HOOK             = 'checkout_firewall_send_attack_start_email';

	public function register(): void {
		add_action( 'action_scheduler_init', array( $this, 'reconcile' ) );
		add_action( self::HOOK, array( $this, 'send' ), 10, 3 );
	}

	/**
	 * Queue the single activation notice.
	 *
	 * @param array<string,mixed> $state Emergency activation state.
	 */
	public function queue( array $state ): void {
		if ( ! $this->enabled() ) {
			return;
		}
		$activation_id = (string) ( $state['activation_id'] ?? '' );
		$stored        = get_option( self::STATE_OPTION, array() );
		if ( is_array( $stored ) && hash_equals( (string) ( $stored['activation_id'] ?? '' ), $activation_id ) && in_array( $stored['status'] ?? null, array( 'accepted', 'failed' ), true ) ) {
			return;
		}
		$args     = array( $activation_id, (string) ( $state['started_at_gmt'] ?? '' ), (string) ( $state['expires_at_gmt'] ?? '' ) );
		$attempts = is_array( $stored ) && hash_equals( (string) ( $stored['activation_id'] ?? '' ), $activation_id ) ? (int) ( $stored['attempts'] ?? 0 ) : 0;
		if ( ! $this->valid_args( $args ) || ! function_exists( 'as_schedule_single_action' ) ) {
			Health::record( 'mail', 'schedule_unavailable' );
			return;
		}
		if ( function_exists( 'as_has_scheduled_action' ) && as_has_scheduled_action( self::HOOK, $args, EmergencyMode::GROUP ) ) {
			return;
		}
		$id = as_schedule_single_action( time() + 1, self::HOOK, $args, EmergencyMode::GROUP, true );
		if ( 0 === (int) $id ) {
			Health::record( 'mail', 'schedule_failed' );
			return;
		}
		$this->write_state( $activation_id, 'queued', $attempts );
	}

	public function reconcile(): void {
		$mode  = new EmergencyMode();
		$state = $mode->state();
		if ( null === $state || ! $mode->is_active() ) {
			return;
		}
		$this->queue( $state );
	}

	public function send( string $activation_id, string $started_at_gmt, string $expires_at_gmt ): void {
		$args = array( $activation_id, $started_at_gmt, $expires_at_gmt );
		if ( ! $this->enabled() || ! $this->valid_args( $args ) ) {
			return;
		}
		$state = get_option( self::STATE_OPTION, array() );
		if ( is_array( $state ) && 'accepted' === ( $state['status'] ?? null ) && hash_equals( (string) ( $state['activation_id'] ?? '' ), $activation_id ) ) {
			return;
		}
		$attempts = is_array( $state ) && hash_equals( (string) ( $state['activation_id'] ?? '' ), $activation_id ) ? (int) ( $state['attempts'] ?? 0 ) : 0;
		if ( $attempts > 1 ) {
			return;
		}
		$recipient = $this->recipient();
		if ( '' === $recipient ) {
			$this->write_state( $activation_id, 'failed', $attempts + 1 );
			Health::record( 'mail', 'recipient_invalid' );
			return;
		}
		$site    = preg_replace( '/[\r\n]+/', ' ', wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES ) );
		$site    = substr( is_string( $site ) ? $site : '', 0, 150 );
		$subject = sprintf( '[Checkout Firewall] Emergency Mode started on %s', $site );
		$message = implode(
			"\n\n",
			array(
				'Emergency Mode was started manually.',
				sprintf( 'Guest checkout requires a fresh Turnstile challenge until %s UTC.', $expires_at_gmt ),
				'Your payment gateway has not been disabled or changed.',
				'This notice does not determine that a checkout or customer is fraudulent.',
				'Review: ' . admin_url( 'admin.php?page=checkout-firewall' ),
				'A Codeprint product.',
				'Checkout Firewall is an independent Codeprint product, not affiliated with or endorsed by Automattic Inc. WooCommerce is a trademark of Automattic Inc. Cloudflare and Turnstile are trademarks of Cloudflare, Inc.',
			)
		);
		try {
			if ( wp_mail( $recipient, $subject, $message ) ) {
				$this->write_state( $activation_id, 'accepted', $attempts + 1 );
				Health::clear( 'mail' );
				return;
			}
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'attack_start_mail_failed', $exception );
		}
		if ( 0 === $attempts && function_exists( 'as_schedule_single_action' ) ) {
			$id = as_schedule_single_action( time() + 300, self::HOOK, $args, EmergencyMode::GROUP, true );
			if ( 0 === (int) $id ) {
				$this->write_state( $activation_id, 'failed', 1 );
				Health::record( 'mail', 'retry_schedule_failed' );
				return;
			}
			$this->write_state( $activation_id, 'queued', 1 );
			return;
		}
		$this->write_state( $activation_id, 'failed', $attempts + 1 );
		Health::record( 'mail', 'send_failed' );
	}

	public function enabled(): bool {
		$value = get_option( self::ENABLED_OPTION, '1' );
		return true === $value || 1 === $value || '1' === $value || 'yes' === $value;
	}

	public function recipient(): string {
		$value = get_option( self::RECIPIENT_OPTION, get_option( 'admin_email', '' ) );
		$value = is_string( $value ) ? sanitize_email( $value ) : '';
		return '' !== $value && strlen( $value ) <= 254 && is_email( $value ) ? $value : '';
	}

	/**
	 * Validate the exact scheduler argument tuple.
	 *
	 * @param list<string> $args Scheduler arguments.
	 */
	private function valid_args( array $args ): bool {
		return 3 === count( $args )
			&& 1 === preg_match( '/^[a-f0-9]{32}$/D', $args[0] )
			&& 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $args[1] )
			&& 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $args[2] )
			&& false !== strtotime( $args[1] . ' UTC' )
			&& false !== strtotime( $args[2] . ' UTC' )
			&& strtotime( $args[2] . ' UTC' ) > strtotime( $args[1] . ' UTC' );
	}

	private function write_state( string $activation_id, string $status, int $attempts ): void {
		$value = array(
			'format'         => 1,
			'activation_id'  => $activation_id,
			'status'         => $status,
			'attempts'       => max( 0, min( 2, $attempts ) ),
			'updated_at_gmt' => gmdate( 'Y-m-d H:i:s' ),
		);
		if ( false === get_option( self::STATE_OPTION, false ) ) {
			add_option( self::STATE_OPTION, $value, '', false );
			return;
		}
		update_option( self::STATE_OPTION, $value, false );
	}
}
