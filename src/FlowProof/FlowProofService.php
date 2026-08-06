<?php
/**
 * Mint and validate the fixed checkout-flow proof protocol.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

final class FlowProofService {
	public const PREFIX         = 'cfwp1';
	public const ACTION         = 'checkout';
	public const TTL_SECONDS    = 300;
	public const FUTURE_SKEW    = 30;
	public const MAX_TOKEN_SIZE = 2048;

	private ProofKeyDeriver $keys;
	private ProofClock $clock;
	/**
	 * Optional deterministic random-byte provider.
	 *
	 * @var null|\Closure(int):string
	 */
	private ?\Closure $random;

	public function __construct( ?ProofKeyDeriver $keys = null, ?ProofClock $clock = null, ?callable $random = null ) {
		$this->keys   = $keys ?? new ProofKeyDeriver();
		$this->clock  = $clock ?? new ProofClock();
		$this->random = null === $random ? null : \Closure::fromCallable( $random );
	}

	/**
	 * Mint a proof for one server-owned checkout binding.
	 *
	 * @return array{proof:string,expires_at:int}
	 * @throws \RuntimeException When key, time, random, or encoding state is invalid.
	 */
	public function mint( CartBinding $binding ): array {
		$now     = $this->clock->now();
		$version = $this->keys->current_version();
		$random  = null === $this->random ? random_bytes( 16 ) : ( $this->random )( 16 );
		if ( 16 !== strlen( $random ) ) {
			throw new \RuntimeException( 'Checkout-flow proof random source is invalid.' );
		}

		$session_key = $this->keys->derive( ProofKeyDeriver::SESSION_CONTEXT, $version )['material'];
		$cart_key    = $this->keys->derive( ProofKeyDeriver::CART_CONTEXT, $version )['material'];
		$claims      = array(
			'jti'          => Base64Url::encode( $random ),
			'session_hash' => Base64Url::encode( hash_hmac( 'sha256', $binding->session_source(), $session_key, true ) ),
			'cart_hash'    => Base64Url::encode( hash_hmac( 'sha256', $binding->cart_source(), $cart_key, true ) ),
			'action'       => self::ACTION,
			'host'         => $binding->host(),
			'issued_at'    => $now,
			'expires_at'   => $now + self::TTL_SECONDS,
			'key_version'  => $version,
		);
		$payload     = self::encode_claims( $claims );
		$signing     = $this->keys->derive( ProofKeyDeriver::SIGN_CONTEXT, $version )['material'];
		$signed      = self::PREFIX . '.' . $payload;
		$proof       = $signed . '.' . Base64Url::encode( hash_hmac( 'sha256', $signed, $signing, true ) );
		if ( strlen( $proof ) > self::MAX_TOKEN_SIZE ) {
			throw new \RuntimeException( 'Checkout-flow proof exceeded its output bound.' );
		}

		return array(
			'proof'      => $proof,
			'expires_at' => $claims['expires_at'],
		);
	}

	/**
	 * Validate stateless proof properties and derive the atomic-consumption row.
	 *
	 * @return array{status:string,token_hash?:string,context_hash?:string,key_version?:int,key_fingerprint?:string,expires_at?:int}
	 * @throws InvalidProofException For an expected invalid proof.
	 */
	public function validate( string $proof, CartBinding $binding ): array {
		if ( '' === $proof || strlen( $proof ) > self::MAX_TOKEN_SIZE ) {
			throw new InvalidProofException();
		}
		$segments = explode( '.', $proof );
		if ( 3 !== count( $segments ) || self::PREFIX !== $segments[0] || '' === $segments[1] || '' === $segments[2] ) {
			throw new InvalidProofException();
		}

		$payload_json = Base64Url::decode( $segments[1] );
		$signature    = Base64Url::decode( $segments[2] );
		if ( strlen( $payload_json ) > 1536 || 32 !== strlen( $signature ) ) {
			throw new InvalidProofException();
		}

		$claims = json_decode( $payload_json, true, 16, JSON_BIGINT_AS_STRING );
		if ( ! is_array( $claims ) || array_keys( $claims ) !== array( 'jti', 'session_hash', 'cart_hash', 'action', 'host', 'issued_at', 'expires_at', 'key_version' ) ) {
			throw new InvalidProofException();
		}
		self::validate_claim_types( $claims );
		if ( ! hash_equals( $segments[1], self::encode_claims( $claims ) ) ) {
			throw new InvalidProofException();
		}

		$version = $claims['key_version'];
		try {
			$signing_record = $this->keys->derive( ProofKeyDeriver::SIGN_CONTEXT, $version );
		} catch ( \OutOfBoundsException $exception ) {
			throw new InvalidProofException();
		}
		$signed   = self::PREFIX . '.' . $segments[1];
		$expected = hash_hmac( 'sha256', $signed, $signing_record['material'], true );
		if ( ! hash_equals( $expected, $signature ) ) {
			throw new InvalidProofException();
		}

		$issued_at  = $claims['issued_at'];
		$expires_at = $claims['expires_at'];
		$now        = $this->clock->now();
		if ( $issued_at < 1 || $expires_at <= $issued_at || ( $expires_at - $issued_at ) > self::TTL_SECONDS || $issued_at > ( $now + self::FUTURE_SKEW ) ) {
			throw new InvalidProofException();
		}
		if ( self::ACTION !== $claims['action'] || ! hash_equals( $binding->host(), $claims['host'] ) ) {
			throw new InvalidProofException();
		}

		$jti          = Base64Url::decode( $claims['jti'] );
		$session_hash = Base64Url::decode( $claims['session_hash'] );
		$cart_hash    = Base64Url::decode( $claims['cart_hash'] );
		if ( 16 !== strlen( $jti ) || 32 !== strlen( $session_hash ) || 32 !== strlen( $cart_hash ) ) {
			throw new InvalidProofException();
		}

		$session_key      = $this->keys->derive( ProofKeyDeriver::SESSION_CONTEXT, $version )['material'];
		$cart_key         = $this->keys->derive( ProofKeyDeriver::CART_CONTEXT, $version )['material'];
		$expected_session = hash_hmac( 'sha256', $binding->session_source(), $session_key, true );
		$expected_cart    = hash_hmac( 'sha256', $binding->cart_source(), $cart_key, true );
		if ( ! hash_equals( $expected_session, $session_hash ) || ! hash_equals( $expected_cart, $cart_hash ) ) {
			throw new InvalidProofException();
		}
		if ( $expires_at <= $now ) {
			return array( 'status' => 'expired' );
		}

		$token_key   = $this->keys->derive( ProofKeyDeriver::TOKEN_CONTEXT, $version )['material'];
		$context_key = $this->keys->derive( ProofKeyDeriver::CONTEXT_CONTEXT, $version )['material'];
		$context     = $session_hash . $cart_hash . "\0" . self::ACTION . "\0" . $claims['host'];
		return array(
			'status'          => 'valid',
			'token_hash'      => hash_hmac( 'sha256', $jti, $token_key, true ),
			'context_hash'    => hash_hmac( 'sha256', $context, $context_key, true ),
			'key_version'     => $version,
			'key_fingerprint' => $signing_record['key_fingerprint'],
			'expires_at'      => $expires_at,
		);
	}

	/**
	 * Validate the exact decoded claim types and bounds.
	 *
	 * @param array<string,mixed> $claims Decoded claims.
	 * @throws InvalidProofException When a claim is outside the protocol.
	 */
	private static function validate_claim_types( array $claims ): void {
		foreach ( array( 'jti', 'session_hash', 'cart_hash', 'action', 'host' ) as $key ) {
			if ( ! is_string( $claims[ $key ] ) ) {
				throw new InvalidProofException();
			}
		}
		foreach ( array( 'issued_at', 'expires_at', 'key_version' ) as $key ) {
			if ( ! is_int( $claims[ $key ] ) ) {
				throw new InvalidProofException();
			}
		}
		if ( strlen( $claims['jti'] ) > 64 || strlen( $claims['session_hash'] ) > 64 || strlen( $claims['cart_hash'] ) > 64
			|| strlen( $claims['action'] ) > 32 || '' === $claims['host'] || strlen( $claims['host'] ) > 253
			|| $claims['key_version'] < 1 || $claims['key_version'] > 32
		) {
			throw new InvalidProofException();
		}
	}

	/**
	 * Encode claims into the canonical payload segment.
	 *
	 * @param array<string,mixed> $claims Ordered claims.
	 * @throws \RuntimeException When JSON encoding fails.
	 */
	private static function encode_claims( array $claims ): string {
		$json = wp_json_encode( $claims, JSON_UNESCAPED_SLASHES );
		if ( ! is_string( $json ) ) {
			throw new \RuntimeException( 'Checkout-flow proof claims could not be encoded.' );
		}
		return Base64Url::encode( $json );
	}
}
