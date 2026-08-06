<?php
/**
 * Classic Checkout Turnstile recovery fields and local assets.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

final class TurnstileClassicClient {
	public const TOKEN_FIELD = 'checkout_firewall_turnstile_token';
	public const STATE_FIELD = 'checkout_firewall_turnstile_state';
	private const CORE       = 'checkout-firewall-turnstile-core';
	private const CLIENT     = 'checkout-firewall-turnstile-classic';

	private TurnstileConfig $config;
	private TurnstileConflictDetector $conflicts;

	public function __construct( TurnstileConfig $config, TurnstileConflictDetector $conflicts ) {
		$this->config    = $config;
		$this->conflicts = $conflicts;
	}

	public function register(): void {
		add_action( 'woocommerce_checkout_before_customer_details', array( $this, 'render' ), 1 );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue' ), 21 );
	}

	public function render(): void {
		if ( ! $this->available() ) {
			return;
		}
		echo '<input type="hidden" name="' . esc_attr( self::TOKEN_FIELD ) . '" id="' . esc_attr( self::TOKEN_FIELD ) . '" value="" />';
		echo '<input type="hidden" name="' . esc_attr( self::STATE_FIELD ) . '" id="' . esc_attr( self::STATE_FIELD ) . '" value="" />';
		echo '<div id="cf-turnstile-classic" class="cf-turnstile-panel" hidden aria-live="polite"></div>';
	}

	public function enqueue(): void {
		if ( ! $this->available() || ! function_exists( 'is_checkout' ) || ! is_checkout()
			|| ( function_exists( 'is_wc_endpoint_url' ) && is_wc_endpoint_url() )
			|| ( function_exists( 'has_block' ) && has_block( 'woocommerce/checkout' ) )
		) {
			return;
		}
		self::register_assets();
		wp_enqueue_script( self::CLIENT );
		wp_enqueue_style( 'checkout-firewall-turnstile-checkout' );
		wp_add_inline_script( self::CLIENT, 'window.checkoutFirewallTurnstile=' . wp_json_encode( self::script_data(), JSON_UNESCAPED_SLASHES ) . ';', 'before' );
	}

	public static function register_assets(): void {
		wp_register_script( self::CORE, plugins_url( 'assets/js/checkout-turnstile-core.js', CHECKOUT_FIREWALL_PLUGIN_FILE ), array(), CHECKOUT_FIREWALL_VERSION, true );
		wp_register_script( self::CLIENT, plugins_url( 'assets/js/checkout-turnstile-classic.js', CHECKOUT_FIREWALL_PLUGIN_FILE ), array( 'jquery', 'wc-checkout', self::CORE ), CHECKOUT_FIREWALL_VERSION, true );
		wp_register_style( 'checkout-firewall-turnstile-checkout', plugins_url( 'assets/css/checkout-firewall-checkout.css', CHECKOUT_FIREWALL_PLUGIN_FILE ), array(), CHECKOUT_FIREWALL_VERSION );
	}

	/**
	 * Return static, cache-safe Classic client data.
	 *
	 * @return array<string,mixed>
	 */
	private static function script_data(): array {
		return array(
			'endpoint'   => rest_url( ChallengeEndpoint::NAMESPACE . ChallengeEndpoint::ROUTE ),
			'tokenField' => self::TOKEN_FIELD,
			'stateField' => self::STATE_FIELD,
			'mount'      => 'cf-turnstile-classic',
			'strings'    => self::script_strings(),
		);
	}

	/**
	 * Return translated shopper-facing Turnstile messages.
	 *
	 * @return array<string,string>
	 */
	public static function script_strings(): array {
		return array(
			'expired'     => __( 'The check expired. Complete the refreshed check to continue.', 'checkout-firewall' ),
			'error'       => __( 'The check could not load. Try the check again.', 'checkout-firewall' ),
			'unavailable' => __( 'The check could not load. Try again.', 'checkout-firewall' ),
		);
	}

	private function available(): bool {
		return $this->config->is_active() && ! $this->conflicts->has_conflict();
	}
}
