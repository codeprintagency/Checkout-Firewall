<?php
/**
 * Store API schema and Checkout Blocks integration registration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

final class CheckoutBlocksRegistrar {
	public function __construct( private ?\Codeprint\CheckoutFirewall\Challenge\PreflightPolicy $preflight = null ) {}
	public function register(): void {
		add_action( 'woocommerce_blocks_loaded', array( $this, 'register_schema' ) );
		add_action( 'woocommerce_blocks_checkout_block_registration', array( $this, 'register_integration' ) );
	}

	public function register_schema(): void {
		if ( ! function_exists( 'woocommerce_store_api_register_endpoint_data' )
			|| ! class_exists( '\\Automattic\\WooCommerce\\StoreApi\\Schemas\\V1\\CheckoutSchema' )
		) {
			return;
		}

		woocommerce_store_api_register_endpoint_data(
			array(
				'endpoint'        => \Automattic\WooCommerce\StoreApi\Schemas\V1\CheckoutSchema::IDENTIFIER,
				'namespace'       => 'checkout-firewall',
				'data_callback'   => static fn(): array => array(
					'flow_proof'      => '',
					'challenge_token' => '',
					'challenge_state' => '',
					'evidence_token'  => '',
					'honeypot_field'  => '',
					'honeypot_value'  => '',
					'turnstile_token' => '',
					'turnstile_state' => '',
				),
				'schema_callback' => array( $this, 'schema' ),
				'schema_type'     => ARRAY_A,
			)
		);
	}

	/**
	 * Return the exact namespaced checkout extension schema.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public function schema(): array {
		return array(
			'flow_proof'      => array(
				'description' => __( 'Checkout-flow proof for the current checkout context.', 'checkout-firewall' ),
				'type'        => 'string',
				'context'     => array( 'view', 'edit' ),
				'maxLength'   => FlowProofService::MAX_TOKEN_SIZE,
			),
			'challenge_token' => array(
				'description' => __( 'Selected-provider response for a pending Checkout Firewall challenge.', 'checkout-firewall' ),
				'type'        => 'string',
				'context'     => array( 'view', 'edit' ),
				'maxLength'   => \Codeprint\CheckoutFirewall\Challenge\LocalProofService::MAX_PAYLOAD,
			),
			'challenge_state' => array(
				'description' => __( 'Opaque pending Checkout Firewall challenge state.', 'checkout-firewall' ),
				'type'        => 'string',
				'context'     => array( 'view', 'edit' ),
				'maxLength'   => \Codeprint\CheckoutFirewall\Challenge\ChallengeCandidateProvider::MAX_STATE,
			),
			'evidence_token'  => array(
				'description' => __( 'Signed browser timing and honeypot evidence.', 'checkout-firewall' ),
				'type'        => 'string',
				'context'     => array( 'view', 'edit' ),
				'maxLength'   => CheckoutEvidenceService::MAX_TOKEN,
			),
			'honeypot_field'  => array(
				'description' => __( 'Randomized checkout honeypot field name.', 'checkout-firewall' ),
				'type'        => 'string',
				'context'     => array( 'view', 'edit' ),
				'maxLength'   => 40,
			),
			'honeypot_value'  => array(
				'description' => __( 'Checkout honeypot field value.', 'checkout-firewall' ),
				'type'        => 'string',
				'context'     => array( 'view', 'edit' ),
				'maxLength'   => 256,
			),
			'turnstile_token' => array(
				'description' => __( 'Turnstile response for a pending Checkout Firewall challenge.', 'checkout-firewall' ),
				'type'        => 'string',
				'context'     => array( 'view', 'edit' ),
				'maxLength'   => \Codeprint\CheckoutFirewall\Turnstile\SiteverifyClient::MAX_TOKEN,
			),
			'turnstile_state' => array(
				'description' => __( 'Opaque pending Checkout Firewall challenge state.', 'checkout-firewall' ),
				'type'        => 'string',
				'context'     => array( 'view', 'edit' ),
				'maxLength'   => \Codeprint\CheckoutFirewall\Turnstile\TurnstileProvider::MAX_STATE,
			),
		);
	}

	/**
	 * Register the frontend script integration.
	 *
	 * @param mixed $registry WooCommerce Blocks integration registry.
	 */
	public function register_integration( $registry ): void {
		if ( is_object( $registry ) && method_exists( $registry, 'register' ) ) {
			$registry->register( new CheckoutBlocksIntegration( $this->preflight ) );
		}
	}
}
