<?php
/**
 * Cache-safe checkout-flow proof mint endpoint.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class MintEndpoint {
	public const NAMESPACE = 'wc/store/v1';
	public const ROUTE     = '/checkout-firewall/flow-proof';

	private FlowProofService $service;
	private CheckoutEvidenceService $evidence;

	public function __construct( ?FlowProofService $service = null, ?CheckoutEvidenceService $evidence = null ) {
		$this->service  = $service ?? new FlowProofService();
		$this->evidence = $evidence ?? new CheckoutEvidenceService();
	}

	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_route' ) );
	}

	public function register_route(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			array(
				'methods'             => \WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'mint' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	public function mint( \WP_REST_Request $request ): \WP_REST_Response {
		$action = $request->get_param( 'action' );
		if ( ! is_string( $action ) || FlowProofService::ACTION !== $action ) {
			return self::response( array( 'code' => 'checkout_firewall_invalid_proof_request' ), 400 );
		}

		try {
			self::load_checkout_cart();
			$binding = CartBinding::from_woocommerce();
			$mint    = array_merge( $this->service->mint( $binding ), $this->evidence->mint( $binding ) );
			return self::response( $mint, 200 );
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'flow_proof_mint_failed', $exception );
			return self::response( array( 'code' => 'checkout_firewall_proof_unavailable' ), 503 );
		}
	}

	/**
	 * Load WooCommerce's cookie or Cart Token session for this custom Store API route.
	 *
	 * @throws \RuntimeException When WooCommerce cannot provide a loaded cart.
	 */
	public static function load_checkout_cart(): void {
		if ( ! function_exists( 'wc_load_cart' ) ) {
			throw new \RuntimeException( 'WooCommerce cart loader is unavailable.' );
		}
		if ( ! did_action( 'woocommerce_load_cart_from_session' ) ) {
			wc_load_cart();
		}
		if ( ! is_object( WC()->cart ) || ! is_object( WC()->session ) ) {
			throw new \RuntimeException( 'WooCommerce checkout cart is unavailable.' );
		}
		WC()->cart->get_cart();
	}

	/**
	 * Build a response with the complete no-store contract.
	 *
	 * @param array<string,mixed> $data Public response body.
	 */
	private static function response( array $data, int $status ): \WP_REST_Response {
		$response = new \WP_REST_Response( $data, $status );
		$response->header( 'Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0' );
		$response->header( 'Pragma', 'no-cache' );
		$response->header( 'Expires', 'Wed, 11 Jan 1984 05:00:00 GMT' );
		$response->header( 'CDN-Cache-Control', 'no-store' );
		$response->header( 'Cloudflare-CDN-Cache-Control', 'no-store' );
		$response->header( 'Surrogate-Control', 'no-store' );
		return $response;
	}
}
