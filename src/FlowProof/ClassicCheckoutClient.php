<?php
/**
 * Classic Checkout hidden field and browser asset.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

final class ClassicCheckoutClient {
	public const FIELD               = 'checkout_firewall_flow_proof';
	public const EVIDENCE_FIELD      = 'checkout_firewall_evidence';
	public const HONEYPOT_NAME_FIELD = 'checkout_firewall_honeypot_name';
	public const HONEYPOT_ID         = 'checkout_firewall_honeypot';

	private const SCRIPT = 'checkout-firewall-flow-proof-classic';

	private const CORE_SCRIPT = 'checkout-firewall-flow-proof-core';

	public function register(): void {
		add_action( 'woocommerce_checkout_before_customer_details', array( $this, 'render_field' ), 0 );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue' ), 20 );
	}

	public function render_field(): void {
		echo '<input type="hidden" name="' . esc_attr( self::FIELD ) . '" id="' . esc_attr( self::FIELD ) . '" value="" />';
		echo '<input type="hidden" name="' . esc_attr( self::EVIDENCE_FIELD ) . '" id="' . esc_attr( self::EVIDENCE_FIELD ) . '" value="" />';
		echo '<input type="hidden" name="' . esc_attr( self::HONEYPOT_NAME_FIELD ) . '" id="' . esc_attr( self::HONEYPOT_NAME_FIELD ) . '" value="" />';
		echo '<input type="text" id="' . esc_attr( self::HONEYPOT_ID ) . '" value="" tabindex="-1" autocomplete="off" aria-hidden="true" data-lpignore="true" data-1p-ignore="true" class="cf-checkout-honeypot" />';
	}

	public function enqueue(): void {
		if ( ! function_exists( 'is_checkout' ) || ! is_checkout() || ( function_exists( 'is_wc_endpoint_url' ) && is_wc_endpoint_url() ) ) {
			return;
		}
		if ( function_exists( 'has_block' ) && has_block( 'woocommerce/checkout' ) ) {
			return;
		}

		wp_register_script(
			self::CORE_SCRIPT,
			plugins_url( 'assets/js/checkout-flow-proof-core.js', CWF_PLUGIN_FILE ),
			array(),
			CWF_VERSION,
			true
		);
		wp_enqueue_script(
			self::SCRIPT,
			plugins_url( 'assets/js/checkout-flow-proof-classic.js', CWF_PLUGIN_FILE ),
			array( 'jquery', 'wc-checkout', self::CORE_SCRIPT ),
			CWF_VERSION,
			true
		);
		wp_add_inline_script(
			self::SCRIPT,
			'window.checkoutFirewallFlowProof=' . wp_json_encode( self::script_data(), JSON_UNESCAPED_SLASHES ) . ';',
			'before'
		);
	}

	/**
	 * Return cache-safe static client configuration.
	 *
	 * @return array<string,mixed>
	 */
	public static function script_data(): array {
		return array(
			'endpoint'          => rest_url( MintEndpoint::NAMESPACE . MintEndpoint::ROUTE ),
			'action'            => FlowProofService::ACTION,
			'field'             => self::FIELD,
			'evidenceField'     => self::EVIDENCE_FIELD,
			'honeypotNameField' => self::HONEYPOT_NAME_FIELD,
			'honeypotId'        => self::HONEYPOT_ID,
			'refreshLeadMs'     => 60000,
		);
	}
}
