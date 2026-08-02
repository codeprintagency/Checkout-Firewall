<?php
/**
 * Cache-safe pending challenge descriptor endpoint.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

use Codeprint\CheckoutFirewall\FlowProof\MintEndpoint;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class ChallengeEndpoint {
	public const NAMESPACE = 'wc/store/v1';
	public const ROUTE     = '/checkout-firewall/turnstile-challenge';

	private ChallengeCoordinator $challenges;

	public function __construct( ChallengeCoordinator $challenges ) {
		$this->challenges = $challenges;
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

	public function describe(): \WP_REST_Response {
		try {
			MintEndpoint::load_checkout_cart();
			$descriptor = $this->challenges->descriptor();
			if ( null === $descriptor ) {
				return self::response( array( 'code' => 'checkout_firewall_challenge_not_found' ), 404 );
			}
			return self::response( $descriptor, 200 );
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'turnstile_challenge_descriptor_failed', $exception );
			return self::response( array( 'code' => 'checkout_firewall_challenge_not_found' ), 404 );
		}
	}

	/**
	 * Build a descriptor response with complete no-store headers.
	 *
	 * @param array<string,mixed> $data Public response body.
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
