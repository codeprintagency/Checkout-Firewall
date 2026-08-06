<?php
/**
 * Capability- and nonce-protected selected-provider and reCAPTCHA actions.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Security\RequestNormalizer;
use Codeprint\CheckoutFirewall\Recaptcha\RecaptchaConfig;
use Codeprint\CheckoutFirewall\Recaptcha\SiteverifyClient;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Turnstile\SiteverifyResult;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;

final class ChallengeSettingsController {
	public const SELECT_ACTION = 'checkout_firewall_select_challenge';
	public const SAVE_ACTION   = 'checkout_firewall_save_recaptcha';
	public const VERIFY_ACTION = 'checkout_firewall_verify_recaptcha';
	public const NONCE_ACTION  = 'checkout_firewall_challenge_settings';

	private ChallengeConfig $challenges;
	private RecaptchaConfig $recaptcha;
	private EmergencyMode $emergency;
	private SiteverifyClient $client;

	public function __construct( ChallengeConfig $challenges, RecaptchaConfig $recaptcha, EmergencyMode $emergency, ?SiteverifyClient $client = null ) {
		$this->challenges = $challenges;
		$this->recaptcha  = $recaptcha;
		$this->emergency  = $emergency;
		$this->client     = $client ?? new SiteverifyClient();
	}

	public function register(): void {
		add_action( 'admin_post_' . self::SELECT_ACTION, array( $this, 'select' ) );
		add_action( 'admin_post_' . self::SAVE_ACTION, array( $this, 'save' ) );
		add_action( 'admin_post_' . self::VERIFY_ACTION, array( $this, 'verify' ) );
	}

	public function select(): void {
		$this->authorize();
		if ( $this->emergency->is_active() ) {
			$this->redirect( 'emergency_active' );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified by authorize() before exact scalar read.
		$provider_input = RequestNormalizer::post( 'challenge_provider', 32 );
		$provider       = $provider_input['invalid'] || null === $provider_input['value'] ? '' : sanitize_key( $provider_input['value'] );
		try {
			$this->challenges->select( $provider );
			$this->redirect( 'challenge_selected' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'challenge_invalid' );
		}
	}

	public function save(): void {
		$this->authorize();
		if ( $this->emergency->is_active() ) {
			$this->redirect( 'emergency_active' );
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Verified by authorize() before exact scalar reads.
		$remove = RequestNormalizer::post( 'remove', 1 );
		if ( ! $remove['invalid'] && '1' === $remove['value'] ) {
			$this->recaptcha->remove();
			$this->redirect( 'recaptcha_removed' );
		}
		$site_input   = RequestNormalizer::post( 'site_key', 256 );
		$secret_input = RequestNormalizer::post( 'secret_key', 256 );
		$site         = $site_input['invalid'] || null === $site_input['value'] ? '' : $site_input['value'];
		$secret       = $secret_input['invalid'] ? null : $secret_input['value'];
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		try {
			$this->recaptcha->save( $site, $secret );
			$this->redirect( 'recaptcha_saved' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'recaptcha_invalid' );
		}
	}

	public function verify(): void {
		$this->authorize();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified by authorize() before exact scalar read.
		$token_input = RequestNormalizer::post( 'health_token', 2048 );
		$token       = $token_input['invalid'] || null === $token_input['value'] ? '' : $token_input['value'];
		$credentials = $this->recaptcha->credentials();
		$host        = TurnstileConfig::current_hostname();
		$result      = $this->client->verify( $token, $credentials['secret_key'], $host );
		if ( $result->is_valid() ) {
			try {
				$this->recaptcha->verify( $host, true );
					$this->challenges->select( ChallengeConfig::RECAPTCHA );
					Health::clear( 'recaptcha' );
					$this->challenges->recovery()->clear( ChallengeConfig::RECAPTCHA );
				$this->redirect( 'recaptcha_verified' );
			} catch ( \Throwable $exception ) {
				$this->recaptcha->disable();
			}
		}
		$this->recaptcha->disable();
		Health::record( 'recaptcha', $result->classification() );
		$this->redirect( SiteverifyResult::INVALID_SECRET === $result->status() ? 'recaptcha_invalid_secret' : 'recaptcha_verification_failed' );
	}

	private function authorize(): void {
		if ( 'POST' !== RequestNormalizer::request_method() || ! current_user_can( 'manage_woocommerce' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Checkout Firewall.', 'checkout-firewall' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::NONCE_ACTION );
	}

	private function redirect( string $status ): void {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'                     => CheckoutFirewallPage::SLUG,
					'view'                     => 'settings',
					'checkout_firewall_status' => sanitize_key( $status ),
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}
}
