<?php
/**
 * Cache-safe selected-provider challenge descriptor endpoint.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

use Codeprint\CheckoutFirewall\FlowProof\MintEndpoint;
use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;
use Codeprint\CheckoutFirewall\Data\CounterType;
use Codeprint\CheckoutFirewall\Protection\EndpointRateLimiter;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class ChallengeEndpoint {
	public const NAMESPACE = 'wc/store/v1';
	public const ROUTE     = '/checkout-firewall/challenge';

	private ChallengeCoordinator $challenges;
	private ?PreflightPolicy $preflight;
	private ?EndpointRateLimiter $limiter;

	public function __construct( ChallengeCoordinator $challenges, ?PreflightPolicy $preflight = null, ?EndpointRateLimiter $limiter = null ) {
		$this->challenges = $challenges;
		$this->preflight  = $preflight;
		$this->limiter    = $limiter;
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
				'callback'            => array( $this, 'describe' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	public function describe( ?\WP_REST_Request $request = null ): \WP_REST_Response {
		try {
			MintEndpoint::load_checkout_cart();
			if ( null !== $this->limiter ) {
				$limit = $this->limiter->allow( CounterType::CHALLENGE_DESCRIPTOR, 12, 60 );
				if ( ! $limit['allowed'] ) {
					$response = self::response( array( 'code' => 'checkout_firewall_challenge_rate_limited' ), 429 );
					$response->header( 'Retry-After', (string) $limit['retry_after'] );
					return $response;
				}
			}
			$intent = null !== $request ? $request->get_param( 'intent' ) : null;
			if ( 'preflight' === $intent ) {
				if ( null === $this->preflight || ! $this->preflight->required() ) {
					return self::response( array( 'code' => 'checkout_firewall_challenge_not_found' ), 404 );
				}
				$surface_input = $request->get_param( 'surface' );
				if ( ! is_string( $surface_input ) || ! in_array( $surface_input, array( 'classic', 'blocks' ), true ) ) {
					return self::response( array( 'code' => 'checkout_firewall_challenge_not_found' ), 404 );
				}
				$surface  = 'blocks' === $surface_input ? CheckoutSurface::STORE_API : CheckoutSurface::CLASSIC;
				$cart     = WC()->cart;
				$decimals = max( 0, min( 6, (int) wc_get_price_decimals() ) );
				$context  = new CheckoutContext(
					$surface,
					false,
					(int) $cart->get_cart_contents_count(),
					(bool) $cart->needs_payment(),
					max( 0, (int) round( (float) $cart->get_total( 'edit' ) * ( 10 ** $decimals ) ) )
				);
				$this->challenges->issue( $context, true );
			}
			$descriptor = $this->challenges->descriptor();
			return null === $descriptor
				? self::response( array( 'code' => 'checkout_firewall_challenge_not_found' ), 404 )
				: self::response( $descriptor, 200 );
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'challenge_descriptor_failed', $exception );
			return self::response( array( 'code' => 'checkout_firewall_challenge_not_found' ), 404 );
		}
	}

	/**
	 * Build one no-store REST response.
	 *
	 * @param array<string,mixed> $data Response body.
	 */
	private static function response( array $data, int $status ): \WP_REST_Response {
		$response = new \WP_REST_Response( $data, $status );
		foreach ( array(
			'Cache-Control'                => 'no-store, no-cache, must-revalidate, max-age=0',
			'Pragma'                       => 'no-cache',
			'Expires'                      => 'Wed, 11 Jan 1984 05:00:00 GMT',
			'CDN-Cache-Control'            => 'no-store',
			'Cloudflare-CDN-Cache-Control' => 'no-store',
			'Surrogate-Control'            => 'no-store',
		) as $name => $value ) {
			$response->header( $name, $value );
		}
		return $response;
	}
}
