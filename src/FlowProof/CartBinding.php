<?php
/**
 * Server-owned checkout-flow proof binding context.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Security\RequestNormalizer;

final class CartBinding {
	private string $host;
	private string $session_source;
	private string $cart_source;

	public function __construct( string $host, string $session_source, string $cart_source ) {
		$host = strtolower( rtrim( $host, '.' ) );
		if ( '' === $host || strlen( $host ) > 253 || 1 !== preg_match( '/^[a-z0-9.:-]+$/D', $host ) ) {
			throw new \InvalidArgumentException( 'Invalid checkout-flow proof host.' );
		}
		if ( '' === $session_source || '' === $cart_source || strlen( $session_source ) > 512 || strlen( $cart_source ) > 65536 ) {
			throw new \InvalidArgumentException( 'Invalid checkout-flow proof context.' );
		}

		$this->host           = $host;
		$this->session_source = $session_source;
		$this->cart_source    = $cart_source;
	}

	public static function from_woocommerce(): self {
		$woocommerce = WC();
		if ( ! is_object( $woocommerce->session ) || ! method_exists( $woocommerce->session, 'get_customer_id' )
			|| ! is_object( $woocommerce->cart )
		) {
			throw new \RuntimeException( 'WooCommerce checkout context is unavailable.' );
		}

		$host = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		if ( ! is_string( $host ) ) {
			throw new \RuntimeException( 'Canonical checkout host is unavailable.' );
		}

		$session_source = self::build_session_source( $woocommerce->session );
		$cart           = $woocommerce->cart->get_cart();
		if ( array() === $cart ) {
			throw new \RuntimeException( 'Checkout cart is empty.' );
		}

		$projection = array();
		foreach ( $cart as $cart_item_key => $item ) {
			if ( ! is_string( $cart_item_key ) || ! is_array( $item ) || count( $projection ) >= 500 ) {
				throw new \RuntimeException( 'Checkout cart context is invalid.' );
			}

			$variation = array();
			$raw       = $item['variation'] ?? array();
			if ( ! is_array( $raw ) || count( $raw ) > 32 ) {
				throw new \RuntimeException( 'Checkout cart variation context is invalid.' );
			}
			foreach ( $raw as $key => $value ) {
				if ( ! is_string( $key ) || ( ! is_string( $value ) && ! is_int( $value ) && ! is_float( $value ) && ! is_bool( $value ) ) ) {
					throw new \RuntimeException( 'Checkout cart variation value is invalid.' );
				}
				$variation[ $key ] = (string) $value;
			}
			ksort( $variation, SORT_STRING );

			$projection[] = array(
				'key'          => substr( $cart_item_key, 0, 64 ),
				'product_id'   => max( 0, (int) ( $item['product_id'] ?? 0 ) ),
				'variation_id' => max( 0, (int) ( $item['variation_id'] ?? 0 ) ),
				'quantity'     => max( 0, (int) ( $item['quantity'] ?? 0 ) ),
				'variation'    => $variation,
			);
		}
		usort(
			$projection,
			static fn( array $left, array $right ): int => strcmp( $left['key'], $right['key'] )
		);

		$cart_source = wp_json_encode( $projection, JSON_UNESCAPED_SLASHES );
		if ( ! is_string( $cart_source ) || '' === $cart_source || strlen( $cart_source ) > 65536 ) {
			throw new \RuntimeException( 'Checkout cart context could not be encoded.' );
		}

		return new self( $host, $session_source, $cart_source );
	}

	public function host(): string {
		return $this->host;
	}

	public function session_source(): string {
		return $this->session_source;
	}

	public static function session_identifier(): string {
		$woocommerce = WC();
		if ( ! is_object( $woocommerce->session ) || ! method_exists( $woocommerce->session, 'get_customer_id' ) ) {
			throw new \RuntimeException( 'WooCommerce session identity is unavailable.' );
		}
		return self::build_session_source( $woocommerce->session );
	}

	public function cart_source(): string {
		return $this->cart_source;
	}

	/**
	 * Build a canonical source for the loaded WooCommerce session.
	 *
	 * @param object $session Loaded WooCommerce session.
	 * @throws \RuntimeException When no session identity is available.
	 */
	private static function build_session_source( object $session ): string {
		$cart_input = RequestNormalizer::server( 'HTTP_CART_TOKEN', 4096 );
		$cart_token = $cart_input['invalid'] || null === $cart_input['value'] ? '' : wc_clean( $cart_input['value'] );
		$utility    = '\\Automattic\\WooCommerce\\StoreApi\\Utilities\\CartTokenUtils';
		if ( '' !== $cart_token && class_exists( $utility ) && $utility::validate_cart_token( $cart_token ) ) {
			$payload = $utility::get_cart_token_payload( $cart_token );
			$user_id = is_array( $payload ) && isset( $payload['user_id'] ) ? (string) $payload['user_id'] : '';
			if ( '' !== $user_id ) {
				return "store-api\0" . $user_id;
			}
		}

		$customer_id = (string) $session->get_customer_id();
		if ( '' === $customer_id ) {
			throw new \RuntimeException( 'WooCommerce session identity is unavailable.' );
		}

		$source = "cookie\0" . $customer_id;
		if ( is_user_logged_in() ) {
			$login_token = wp_get_session_token();
			if ( '' === $login_token ) {
				throw new \RuntimeException( 'WordPress login session is unavailable.' );
			}
			$source .= "\0login\0" . $login_token;
		}
		return $source;
	}
}
