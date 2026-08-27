<?php
/**
 * Classic Checkout selected-provider recovery fields and assets.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

final class ChallengeClassicClient {
	public const TOKEN_FIELD                   = 'checkout_firewall_challenge_token';
	public const STATE_FIELD                   = 'checkout_firewall_challenge_state';
	private const CORE                         = 'checkout-firewall-challenge-core';
	private const CLIENT                       = 'checkout-firewall-challenge-classic';
	private const STYLE                        = 'checkout-firewall-checkout';
	private static ?PreflightPolicy $preflight = null;

	public function __construct( ?PreflightPolicy $preflight = null ) {
		self::$preflight = $preflight;
	}

	public function register(): void {
		add_action( 'woocommerce_checkout_before_customer_details', array( $this, 'render_fields' ), 1 );
		add_action( 'woocommerce_checkout_before_order_review', array( $this, 'render_panel' ), 5 );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue' ), 21 );
	}

	public function render_fields(): void {
		echo '<input type="hidden" name="' . esc_attr( self::TOKEN_FIELD ) . '" id="' . esc_attr( self::TOKEN_FIELD ) . '" value="" />';
		echo '<input type="hidden" name="' . esc_attr( self::STATE_FIELD ) . '" id="' . esc_attr( self::STATE_FIELD ) . '" value="" />';
	}

	public function render_panel(): void {
		echo '<div id="cf-challenge-classic" class="cf-challenge-panel" hidden aria-live="polite"></div>';
	}

	public function enqueue(): void {
		if ( ! function_exists( 'is_checkout' ) || ! is_checkout()
			|| ( function_exists( 'is_wc_endpoint_url' ) && is_wc_endpoint_url() )
			|| ( function_exists( 'has_block' ) && has_block( 'woocommerce/checkout' ) )
		) {
			return;
		}
		self::register_assets();
		wp_enqueue_script( self::CLIENT );
		wp_enqueue_style( self::STYLE );
		wp_add_inline_script( self::CLIENT, 'window.checkoutFirewallChallenge=' . wp_json_encode( self::script_data(), JSON_UNESCAPED_SLASHES ) . ';', 'before' );
	}

	public static function register_assets(): void {
		wp_register_script( self::CORE, plugins_url( 'assets/js/checkout-challenge-core.js', CHECKOUT_FIREWALL_PLUGIN_FILE ), array(), CHECKOUT_FIREWALL_VERSION, true );
		wp_register_script( self::CLIENT, plugins_url( 'assets/js/checkout-challenge-classic.js', CHECKOUT_FIREWALL_PLUGIN_FILE ), array( 'jquery', 'wc-checkout', self::CORE ), CHECKOUT_FIREWALL_VERSION, true );
		wp_register_style( self::STYLE, plugins_url( 'assets/css/checkout-firewall-checkout.css', CHECKOUT_FIREWALL_PLUGIN_FILE ), array(), CHECKOUT_FIREWALL_VERSION );
	}

	/**
	 * Return cache-safe client configuration.
	 *
	 * @return array<string,mixed>
	 */
	public static function script_data(): array {
		return array(
			'endpoint'    => rest_url( ChallengeEndpoint::NAMESPACE . ChallengeEndpoint::ROUTE ),
			'tokenField'  => self::TOKEN_FIELD,
			'stateField'  => self::STATE_FIELD,
			'mount'       => 'cf-challenge-classic',
			'localScript' => plugins_url( 'assets/vendor/altcha/altcha.js', CHECKOUT_FIREWALL_PLUGIN_FILE ),
			'localWorker' => plugins_url( 'assets/vendor/altcha/pbkdf2.js', CHECKOUT_FIREWALL_PLUGIN_FILE ),
			'localStyle'  => plugins_url( 'assets/vendor/altcha/altcha.css', CHECKOUT_FIREWALL_PLUGIN_FILE ),
			'language'    => strtolower( substr( determine_locale(), 0, 2 ) ),
			'preflight'   => null !== self::$preflight && self::$preflight->required(),
			'surface'     => 'classic',
			'strings'     => self::script_strings(),
		);
	}

	/**
	 * Return translated shopper-facing challenge messages.
	 *
	 * @return array<string,string>
	 */
	public static function script_strings(): array {
		return array(
			'expired'       => __( 'The check expired. Complete the refreshed check to continue.', 'checkout-firewall' ),
			'error'         => __( 'The check could not be completed. Try the check again.', 'checkout-firewall' ),
			'retry'         => __( 'Try security check again', 'checkout-firewall' ),
			'unavailable'   => __( 'The security check could not load. Please try again.', 'checkout-firewall' ),
			'verifying'     => __( 'Checking your browser…', 'checkout-firewall' ),
			'localAria'     => __( 'Visit ALTCHA.org', 'checkout-firewall' ),
			'localAudio'    => __( 'Get an audio challenge', 'checkout-firewall' ),
			'localCode'     => __( 'Enter code', 'checkout-firewall' ),
			'localCodeAria' => __( 'Enter the security code', 'checkout-firewall' ),
			'localFooter'   => __( 'Protected by ALTCHA', 'checkout-firewall' ),
			'localLabel'    => __( 'Verify this browser', 'checkout-firewall' ),
			'localLoading'  => __( 'Loading…', 'checkout-firewall' ),
			'localReload'   => __( 'Reload', 'checkout-firewall' ),
			'localRequired' => __( 'Verification required', 'checkout-firewall' ),
			'localVerified' => __( 'Verified', 'checkout-firewall' ),
			'localVerify'   => __( 'Verify', 'checkout-firewall' ),
			'localWait'     => __( 'Please wait while your browser is verified.', 'checkout-firewall' ),
		);
	}
}
