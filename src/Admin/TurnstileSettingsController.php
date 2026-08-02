<?php
/**
 * Capability- and nonce-protected Turnstile settings actions.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Turnstile\SiteverifyClient;
use Codeprint\CheckoutFirewall\Turnstile\SiteverifyResult;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;

final class TurnstileSettingsController {
	public const SAVE_ACTION   = 'cwf_save_turnstile';
	public const VERIFY_ACTION = 'cwf_verify_turnstile';
	public const NONCE_ACTION  = 'cwf_turnstile_settings';

	private TurnstileConfig $config;
	private SiteverifyClient $client;
	private ?ChallengeConfig $challenges;

	public function __construct( TurnstileConfig $config, ?SiteverifyClient $client = null, ?ChallengeConfig $challenges = null ) {
		$this->config     = $config;
		$this->client     = $client ?? new SiteverifyClient();
		$this->challenges = $challenges;
	}

	public function register(): void {
		add_action( 'admin_post_' . self::SAVE_ACTION, array( $this, 'save' ) );
		add_action( 'admin_post_' . self::VERIFY_ACTION, array( $this, 'verify' ) );
	}

	public function save(): void {
		$this->authorize();
		if ( ( new EmergencyMode( $this->config ) )->is_active() ) {
			$this->redirect( 'emergency_active' );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified by authorize() before exact scalar reads.
		if ( isset( $_POST['remove'] ) && '1' === wp_unslash( $_POST['remove'] ) ) {
			$this->config->remove();
			$this->redirect( 'removed' );
		}
		$site   = isset( $_POST['site_key'] ) && is_string( $_POST['site_key'] ) ? wp_unslash( $_POST['site_key'] ) : '';
		$secret = isset( $_POST['secret_key'] ) && is_string( $_POST['secret_key'] ) ? wp_unslash( $_POST['secret_key'] ) : null;
		if ( defined( 'CWF_TURNSTILE_SITE_KEY' ) ) {
			$site = $this->config->credentials()['site_key'];
		}
		if ( defined( 'CWF_TURNSTILE_SECRET_KEY' ) ) {
			$secret = null;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		try {
			$this->config->save( $site, $secret );
			$this->redirect( 'saved' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'invalid' );
		}
	}

	public function verify(): void {
		$this->authorize();
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified by authorize() before exact scalar read.
		$token = isset( $_POST['health_token'] ) && is_string( $_POST['health_token'] ) ? wp_unslash( $_POST['health_token'] ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		$credentials = $this->config->credentials();
		$host        = TurnstileConfig::current_hostname();
		$result      = $this->client->verify( $token, $credentials['secret_key'], $host, 'checkout_firewall_health', $this->config->health_cdata() );
		if ( $result->is_valid() ) {
			try {
				$this->config->verify( $host, true );
				if ( null !== $this->challenges ) {
					$this->challenges->select( ChallengeConfig::TURNSTILE );
				}
				Health::clear( 'turnstile' );
				if ( null !== $this->challenges ) {
					$this->challenges->recovery()->clear( ChallengeConfig::TURNSTILE );
				}
				$this->redirect( 'verified' );
			} catch ( \Throwable $exception ) {
				$this->config->disable();
				$this->redirect( 'test_keys' );
			}
		}
		$this->config->disable();
		Health::record( 'turnstile', $result->classification() );
		$this->redirect( SiteverifyResult::INVALID_SECRET === $result->status() ? 'invalid_secret' : 'verification_failed' );
	}

	private function authorize(): void {
		if ( 'POST' !== strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) || ! current_user_can( 'manage_woocommerce' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Checkout Firewall.', 'checkout-firewall' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::NONCE_ACTION );
	}

	private function redirect( string $status ): void {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'       => CheckoutFirewallPage::SLUG,
					'view'       => 'settings',
					'cwf_status' => sanitize_key( $status ),
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}
}
