<?php
/**
 * Rate-limited local Free incident email.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class FreeIncidentMailer {
	public const HOOK             = 'checkout_firewall_send_free_incident_email';
	public const COOLDOWN_SECONDS = 43200;

	public function __construct( private FreeIncidentState $state, private ?AttackStartMailer $settings = null ) {
		$this->settings = $settings ?? new AttackStartMailer();
	}

	public function register(): void {
		add_action( self::HOOK, array( $this, 'send' ), 10, 1 );
	}

	/**
	 * Queue an eligible incident notification outside checkout.
	 *
	 * @param array<string,mixed> $incident Incident state.
	 */
	public function queue( array $incident ): void {
		if ( ! $this->settings->enabled() || 'open' !== ( $incident['status'] ?? null ) || 'pending' !== ( $incident['email_status'] ?? null ) || ! function_exists( 'as_schedule_single_action' ) ) {
			return;
		}
		$last = strtotime( (string) ( $incident['last_email_at_gmt'] ?? '' ) . ' UTC' );
		if ( false !== $last && $last > time() - self::COOLDOWN_SECONDS ) {
			return;
		}
		$args = array( (string) $incident['incident_id'] );
		if ( function_exists( 'as_has_scheduled_action' ) && as_has_scheduled_action( self::HOOK, $args, EmergencyMode::GROUP ) ) {
			return;
		}
		as_schedule_single_action( time() + 1, self::HOOK, $args, EmergencyMode::GROUP, true );
	}

	public function send( string $incident_id ): void {
		$state = $this->state->read();
		if ( null === $state || ! hash_equals( $state['incident_id'], $incident_id ) || 'open' !== $state['status'] || 'pending' !== $state['email_status'] || ! $this->settings->enabled() ) {
			return;
		}
		$state['email_status'] = 'sending';
		$this->state->write( $state );
		$state = $this->state->read();
		if ( null === $state || ! hash_equals( $state['incident_id'], $incident_id ) || 'sending' !== $state['email_status'] ) {
			return;
		}
		$recipient = $this->settings->recipient();
		if ( '' === $recipient ) {
			$state['email_status'] = 'failed';
			$this->state->write( $state );
			return;
		}
		$counts = $state['counts'];
		$site   = substr( preg_replace( '/[\r\n]+/', ' ', wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES ) ) ?? '', 0, 150 );
		$body   = implode(
			"\n\n",
			array(
				'Checkout Firewall detected elevated checkout-abuse signals. This does not determine that a checkout or customer is fraudulent.',
				sprintf( 'Window: %s UTC through %s UTC.', (string) $state['first_signal_at_gmt'], (string) $state['last_signal_at_gmt'] ),
				sprintf( 'Actual challenges: %d. Actual blocks: %d. Would challenge in Observe Mode: %d. Would block in Observe Mode: %d.', (int) $counts['enforced_challenge'], (int) $counts['enforced_block'], (int) $counts['observed_challenge'], (int) $counts['observed_block'] ),
				( new OperatingMode() )->is_observing() ? 'Observe Mode did not stop these checkout attempts.' : 'Standard Mode was active for the enforced decisions shown above.',
				'Review: ' . admin_url( 'admin.php?page=checkout-firewall&view=activity' ),
				'A Codeprint product.',
				'Checkout Firewall is an independent Codeprint product, not affiliated with or endorsed by Automattic Inc.',
			)
		);
		try {
			if ( wp_mail( $recipient, sprintf( '[Checkout Firewall] Elevated checkout activity on %s', $site ), $body ) ) {
				$state['email_status']      = 'accepted';
				$state['email_attempts']    = (int) $state['email_attempts'] + 1;
				$state['last_email_at_gmt'] = gmdate( 'Y-m-d H:i:s' );
				$this->state->write( $state );
				return;
			}
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'free_incident_mail_failed', $exception );
		}
		$attempts = (int) $state['email_attempts'];
		if ( 0 === $attempts && function_exists( 'as_schedule_single_action' ) ) {
			$state['email_status']   = 'pending';
			$state['email_attempts'] = 1;
			$this->state->write( $state );
			as_schedule_single_action( time() + 300, self::HOOK, array( $incident_id ), EmergencyMode::GROUP, true );
			return;
		}
		$state['email_status']   = 'failed';
		$state['email_attempts'] = min( 2, $attempts + 1 );
		$this->state->write( $state );
		Health::record( 'mail', 'incident_send_failed' );
	}
}
