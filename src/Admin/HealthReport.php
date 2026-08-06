<?php
/**
 * Bounded read-only M6 health report.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Compatibility\Requirements;
use Codeprint\CheckoutFirewall\Database\Schema;
use Codeprint\CheckoutFirewall\Operations\AttackStartMailer;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;
use Codeprint\CheckoutFirewall\Protection\ClientIpResolver;
use Codeprint\CheckoutFirewall\Protection\CounterRepository;
use Codeprint\CheckoutFirewall\Protection\GatewayHealth;
use Codeprint\CheckoutFirewall\Protection\IdentityRegistry;
use Codeprint\CheckoutFirewall\Recaptcha\RecaptchaConfig;
use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConflictDetector;

final class HealthReport {
	public const OPTION = 'checkout_firewall_admin_health_snapshot';

	/**
	 * Run and store the bounded local health snapshot.
	 *
	 * @return array<string,array{status:string,detail:string}>
	 */
	public function run(): array {
		$keys       = new KeyStore();
		$turnstile  = new TurnstileConfig( $keys );
		$conflicts  = new TurnstileConflictDetector();
		$challenges = new ChallengeConfig( $turnstile, new RecaptchaConfig( $keys ), $conflicts );
		$proxy      = new ClientIpResolver();
		$mode       = new EmergencyMode( $turnstile, $conflicts, null, null, $challenges );
		$operating  = new OperatingMode();
		$mode_state = $operating->state();
		$exemptions = ( new \Codeprint\CheckoutFirewall\Protection\TrustedExemptionStore() )->active();
		$incident   = ( new \Codeprint\CheckoutFirewall\Operations\FreeIncidentState() )->read();
		$schema     = ( new Schema( \Codeprint\CheckoutFirewall\Database\TableNames::from_wordpress() ) )->verify();
		$required   = Requirements::runtime_failure();
		$schedules  = $this->schedules_healthy();
		$mail_state = get_option( AttackStartMailer::STATE_OPTION, array() );
		$health     = get_option( Health::OPTION, array() );
		$emergency  = is_array( $health ) && is_array( $health['emergency'] ?? null ) ? (string) ( $health['emergency']['code'] ?? '' ) : '';
		$rows       = array(
			'requirements' => $this->row( null === $required ? 'healthy' : 'attention', null === $required ? __( 'Runtime requirements are satisfied.', 'checkout-firewall' ) : __( 'A runtime requirement needs attention.', 'checkout-firewall' ) ),
			'schema'       => $this->row( array() === $schema ? 'healthy' : 'attention', array() === $schema ? __( 'Schema v2 is verified.', 'checkout-firewall' ) : __( 'Schema verification found an issue.', 'checkout-firewall' ) ),
			'keys'         => $this->row( $keys->is_healthy() && $keys->validate_references() ? 'healthy' : 'attention', __( 'Local identifier keys and row references.', 'checkout-firewall' ) ),
			'scheduler'    => $this->row( $schedules ? 'healthy' : 'attention', $schedules ? __( 'Cleanup schedules are present.', 'checkout-firewall' ) : __( 'One or more cleanup schedules need attention.', 'checkout-firewall' ) ),
			'turnstile'    => $this->row( $turnstile->is_active() && ! $conflicts->has_conflict() ? 'healthy' : 'inactive', $turnstile->is_active() ? __( 'Turnstile is verified.', 'checkout-firewall' ) : __( 'Turnstile is not active.', 'checkout-firewall' ) ),
			'challenge'    => $this->challenge( $challenges ),
			'emergency'    => 'prerequisite_unavailable' === $emergency
				? $this->row( 'attention', __( 'Emergency Mode ended automatically because checkout recovery became unavailable. Standard Mode remains active.', 'checkout-firewall' ) )
				: $this->row( $mode->is_active() || $operating->is_observing() ? 'attention' : 'inactive', $mode->is_active() ? __( 'Emergency Mode is active and time-boxed.', 'checkout-firewall' ) : ( $operating->is_observing() ? __( 'Observe Mode is measuring decisions but is not challenging or stopping checkout attempts.', 'checkout-firewall' ) : __( 'Standard Mode is active.', 'checkout-firewall' ) ) ),
			'operating'    => $this->row( $operating->is_observing() ? 'attention' : 'healthy', null !== $mode_state && $operating->is_observing() ? sprintf( /* translators: %s: Observe Mode review date in UTC. */ __( 'Observe Mode is non-enforcing. Review it after %s UTC.', 'checkout-firewall' ), (string) $mode_state['review_after_gmt'] ) : sprintf( /* translators: %s: Standard Mode enforcement epoch in UTC. */ __( 'Standard Mode enforcement epoch: %s UTC.', 'checkout-firewall' ), null === $mode_state ? __( 'historical default', 'checkout-firewall' ) : (string) $mode_state['enforcement_epoch_gmt'] ) ),
			'exemptions'   => $this->row( array() === $exemptions ? 'inactive' : 'healthy', sprintf( /* translators: %d: active trusted exemption count. */ __( '%d bounded trusted exemptions are active.', 'checkout-firewall' ), min( 100, count( $exemptions ) ) ) ),
			'incident'     => $this->row( null !== $incident && 'open' === $incident['status'] ? 'attention' : 'inactive', null === $incident ? __( 'No local Free incident has been recorded.', 'checkout-firewall' ) : ( 'open' === $incident['status'] ? __( 'A local elevated-activity incident is open.', 'checkout-firewall' ) : __( 'The most recent local elevated-activity incident is closed.', 'checkout-firewall' ) ) ),
			'proxy'        => $this->visitor_ip( $proxy ),
			'cloudflare'   => $this->edge_protection( $proxy ),
			'mail'         => $this->row( is_array( $mail_state ) && 'failed' === ( $mail_state['status'] ?? null ) ? 'attention' : ( is_array( $mail_state ) && 'accepted' === ( $mail_state['status'] ?? null ) ? 'healthy' : 'inactive' ), is_array( $mail_state ) && 'accepted' === ( $mail_state['status'] ?? null ) ? __( 'Accepted by WordPress mail; delivery is not confirmed.', 'checkout-firewall' ) : __( 'No confirmed mail delivery claim is made.', 'checkout-firewall' ) ),
			'gateways'     => $this->gateways(),
		);
		$value      = array(
			'format'         => 1,
			'checked_at_gmt' => gmdate( 'Y-m-d H:i:s' ),
			'components'     => $rows,
		);
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, $value, '', false );
		} else {
			update_option( self::OPTION, $value, false );
		}
		return $rows;
	}

	/**
	 * Report selected-provider recovery health.
	 *
	 * @return array{status:string,detail:string}
	 */
	private function challenge( ChallengeConfig $challenges ): array {
		if ( ! $challenges->is_available() ) {
			return $this->row( 'attention', __( 'Browser challenge recovery is disabled; recoverable limits use a temporary throttle.', 'checkout-firewall' ) );
		}
		if ( $challenges->is_fallback() ) {
			return $this->row( 'healthy', __( 'The selected external provider is unavailable, so the private local fallback is active.', 'checkout-firewall' ) );
		}
		$details = array(
			ChallengeConfig::LOCAL     => __( 'The private local browser check is active.', 'checkout-firewall' ),
			ChallengeConfig::TURNSTILE => __( 'Cloudflare Turnstile challenge recovery is active.', 'checkout-firewall' ),
			ChallengeConfig::RECAPTCHA => __( 'Google reCAPTCHA challenge recovery is active.', 'checkout-firewall' ),
		);
		return $this->row( 'healthy', $details[ $challenges->effective() ] ?? __( 'Checkout challenge recovery is active.', 'checkout-firewall' ) );
	}

	/**
	 * Report whether visitor-address resolution is safely configured.
	 *
	 * @return array{status:string,detail:string}
	 */
	private function visitor_ip( ClientIpResolver $proxy ): array {
		if ( 'healthy' !== $proxy->configuration_status() ) {
			return $this->row( 'attention', __( 'Visitor IP detection needs a valid trusted-proxy configuration.', 'checkout-firewall' ) );
		}
		return ClientIpResolver::MODE_MANUAL === $proxy->configured_mode()
			? $this->row( 'healthy', __( 'A custom visitor-address header and trusted proxy range list are configured.', 'checkout-firewall' ) )
			: $this->row( 'healthy', __( 'Direct and verified Cloudflare visitor addresses are handled automatically.', 'checkout-firewall' ) );
	}

	/**
	 * Report the optional Cloudflare edge layer without making it a plugin requirement.
	 *
	 * @return array{status:string,detail:string}
	 */
	private function edge_protection( ClientIpResolver $proxy ): array {
		if ( ClientIpResolver::MODE_MANUAL === $proxy->configured_mode() ) {
			return $this->row( 'inactive', __( 'A custom trusted proxy is configured, so Cloudflare auto-detection is bypassed.', 'checkout-firewall' ) );
		}
		$edge = $proxy->edge_status();
		if ( 'cloudflare' === $edge ) {
			return $this->row( 'healthy', __( 'Cloudflare edge protection was detected and its verified visitor-address header is available.', 'checkout-firewall' ) );
		}
		if ( 'cloudflare_header_missing' === $edge ) {
			return $this->row( 'attention', __( 'Cloudflare was detected, but its visitor-address header is unavailable. Check the Cloudflare visitor IP header setting.', 'checkout-firewall' ) );
		}
		if ( 'unknown' === $edge ) {
			return $this->row( 'inactive', __( 'Edge protection could not be determined for this request. Checkout Firewall remains active.', 'checkout-firewall' ) );
		}
		return $this->row( 'inactive', __( 'Cloudflare was not detected on this request. Optional Cloudflare edge protection can add DDoS and bot controls; Checkout Firewall remains active without it.', 'checkout-firewall' ) );
	}

	private function schedules_healthy(): bool {
		if ( ! function_exists( 'as_has_scheduled_action' ) ) {
			return false;
		}
		foreach ( array( 'events', 'counters', 'blocks', 'consumed_tokens' ) as $kind ) {
			if ( ! as_has_scheduled_action( 'checkout_firewall_cleanup_' . $kind, array(), 'checkout-firewall' ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Inspect at most 20 enabled gateways without calling availability filters.
	 *
	 * @return array{status:string,detail:string}
	 */
	private function gateways(): array {
		if ( ! function_exists( 'WC' ) ) {
			return $this->row( 'inactive', __( 'WooCommerce payment gateways are unavailable in this context.', 'checkout-firewall' ) );
		}
		$registered = WC()->payment_gateways()->payment_gateways();
		$ids        = array();
		foreach ( $registered as $gateway ) {
			if ( ! is_object( $gateway ) || 'yes' !== ( $gateway->enabled ?? null ) ) {
				continue;
			}
			$id = isset( $gateway->id ) && is_string( $gateway->id ) ? substr( sanitize_key( $gateway->id ), 0, 64 ) : '';
			if ( '' !== $id ) {
				$ids[] = $id;
			}
			if ( 20 === count( $ids ) ) {
				break;
			}
		}
		if ( array() === $ids ) {
			return $this->row( 'inactive', __( 'No enabled WooCommerce gateway was found.', 'checkout-firewall' ) );
		}
		$health = new GatewayHealth( new CounterRepository(), new IdentityRegistry() );
		foreach ( $ids as $id ) {
			if ( $health->is_outage( $id ) ) {
				return $this->row( 'attention', __( 'A recent enabled-gateway outcome window needs attention. No gateway was changed.', 'checkout-firewall' ) );
			}
		}
		return $this->row( 'healthy', __( 'Enabled gateway outcome windows were checked. No gateway was changed.', 'checkout-firewall' ) );
	}

	/**
	 * Build one closed health component.
	 *
	 * @return array{status:string,detail:string}
	 */
	private function row( string $status, string $detail ): array {
		return array(
			'status' => $status,
			'detail' => $detail,
		);
	}
}
