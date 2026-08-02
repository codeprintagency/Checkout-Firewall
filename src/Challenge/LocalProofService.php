<?php
/**
 * Bounded local ALTCHA-compatible PBKDF2 proof-of-work protocol.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

use Codeprint\CheckoutFirewall\Security\KeyStore;

final class LocalProofService {
	public const MAX_PAYLOAD   = 8192;
	public const ALGORITHM     = 'PBKDF2/SHA-256';
	public const COST          = 5000;
	public const MIN_COUNTER   = 0;
	public const MAX_COUNTER   = 2500;
	private const SIGN_CONTEXT = 'checkout-firewall/challenge/local-signature/v1';
	private const KEY_CONTEXT  = 'checkout-firewall/challenge/local-key-signature/v1';

	private KeyStore $keys;
	/**
	 * Bounded random-counter provider.
	 *
	 * @var \Closure(int,int):int
	 */
	private \Closure $random_int;
	/**
	 * Secure random-byte provider.
	 *
	 * @var \Closure(int):string
	 */
	private \Closure $random_bytes;

	public function __construct( ?KeyStore $keys = null, ?callable $random_int = null, ?callable $random_bytes = null ) {
		$this->keys         = $keys ?? new KeyStore();
		$this->random_int   = \Closure::fromCallable( $random_int ?? 'random_int' );
		$this->random_bytes = \Closure::fromCallable( $random_bytes ?? 'random_bytes' );
	}

	/**
	 * Create one signed, self-hosted challenge descriptor.
	 *
	 * @return array{parameters:array<string,mixed>,signature:string}
	 * @throws \RuntimeException When a safe challenge cannot be created.
	 */
	public function create( string $state, int $expires_at ): array {
		$nonce   = ( $this->random_bytes )( 16 );
		$salt    = ( $this->random_bytes )( 16 );
		$counter = ( $this->random_int )( self::MIN_COUNTER, self::MAX_COUNTER );
		if ( 16 !== strlen( $nonce ) || 16 !== strlen( $salt ) || $counter < self::MIN_COUNTER || $counter > self::MAX_COUNTER ) {
			throw new \RuntimeException( 'Local challenge entropy is unavailable.' );
		}
		$derived = hash_pbkdf2( 'sha256', $nonce . pack( 'N', $counter ), $salt, self::COST, 32, true );
		$params  = array(
			'algorithm'    => self::ALGORITHM,
			'cost'         => self::COST,
			'data'         => array(
				'action' => ChallengeCoordinator::ACTION,
				'state'  => $state,
			),
			'expiresAt'    => $expires_at,
			'keyLength'    => 32,
			'keyPrefix'    => bin2hex( substr( $derived, 0, 16 ) ),
			'keySignature' => $this->hmac( bin2hex( $derived ), self::KEY_CONTEXT ),
			'nonce'        => bin2hex( $nonce ),
			'salt'         => bin2hex( $salt ),
		);
		return array(
			'parameters' => $params,
			'signature'  => $this->hmac( self::canonical_json( $params ), self::SIGN_CONTEXT ),
		);
	}

	public function verify( string $payload, string $state, int $expires_at, int $now ): bool {
		if ( '' === $payload || strlen( $payload ) > self::MAX_PAYLOAD ) {
			return false;
		}
		$decoded = base64_decode( $payload, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decodes the documented ALTCHA response envelope.
		if ( false === $decoded || strlen( $decoded ) > self::MAX_PAYLOAD ) {
			return false;
		}
		$data = json_decode( $decoded, true );
		if ( ! is_array( $data ) || ! is_array( $data['challenge'] ?? null ) || ! is_array( $data['solution'] ?? null ) ) {
			return false;
		}
		$challenge = $data['challenge'];
		$params    = $challenge['parameters'] ?? null;
		$signature = $challenge['signature'] ?? null;
		$solution  = $data['solution'];
		if ( ! is_array( $params ) || ! is_string( $signature ) || 64 !== strlen( $signature ) || ! $this->valid_parameters( $params, $state, $expires_at, $now ) ) {
			return false;
		}
		$expected = $this->hmac( self::canonical_json( $params ), self::SIGN_CONTEXT );
		if ( ! hash_equals( $expected, $signature ) ) {
			return false;
		}
		$counter = $solution['counter'] ?? null;
		$derived = $solution['derivedKey'] ?? null;
		if ( ! is_int( $counter ) || $counter < self::MIN_COUNTER || $counter > self::MAX_COUNTER || ! is_string( $derived ) || 64 !== strlen( $derived ) || 1 !== preg_match( '/^[a-f0-9]{64}$/D', $derived ) ) {
			return false;
		}
		if ( ! hash_equals( (string) $params['keyPrefix'], substr( $derived, 0, 32 ) ) ) {
			return false;
		}
		return hash_equals( (string) $params['keySignature'], $this->hmac( $derived, self::KEY_CONTEXT ) );
	}

	/**
	 * Validate a closed local challenge parameter set.
	 *
	 * @param array<string,mixed> $params Challenge parameters.
	 */
	private function valid_parameters( array $params, string $state, int $expires_at, int $now ): bool {
		$required = array( 'algorithm', 'cost', 'data', 'expiresAt', 'keyLength', 'keyPrefix', 'keySignature', 'nonce', 'salt' );
		$keys     = array_keys( $params );
		sort( $keys );
		sort( $required );
		if ( $required !== $keys || self::ALGORITHM !== ( $params['algorithm'] ?? null ) || self::COST !== ( $params['cost'] ?? null )
			|| 32 !== ( $params['keyLength'] ?? null ) || ( $params['expiresAt'] ?? null ) !== $expires_at || 0 < $now - $expires_at
			|| ! is_array( $params['data'] ) || array(
				'action' => ChallengeCoordinator::ACTION,
				'state'  => $state,
			) !== $params['data']
		) {
			return false;
		}
		foreach ( array(
			'nonce'        => 32,
			'salt'         => 32,
			'keyPrefix'    => 32,
			'keySignature' => 64,
		) as $name => $length ) {
			if ( ! is_string( $params[ $name ] ) || strlen( $params[ $name ] ) !== $length || 1 !== preg_match( '/^[a-f0-9]+$/D', $params[ $name ] ) ) {
				return false;
			}
		}
		return true;
	}

	private function hmac( string $data, string $context ): string {
		$key = $this->keys->derive_challenge_key( $context );
		return hash_hmac( 'sha256', $data, $key['material'] );
	}

	/**
	 * Encode one recursively sorted challenge value.
	 *
	 * @param array<string,mixed> $value Challenge value.
	 * @throws \RuntimeException When JSON encoding fails.
	 */
	private static function canonical_json( array $value ): string {
		self::sort_recursive( $value );
		$json = wp_json_encode( $value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		if ( ! is_string( $json ) ) {
			throw new \RuntimeException( 'Local challenge could not be encoded.' );
		}
		return $json;
	}

	/**
	 * Sort object keys recursively while preserving lists.
	 *
	 * @param array<mixed> $value Value to sort in place.
	 */
	private static function sort_recursive( array &$value ): void {
		if ( range( 0, count( $value ) - 1 ) !== array_keys( $value ) ) {
			ksort( $value );
		}
		foreach ( $value as &$item ) {
			if ( is_array( $item ) ) {
				self::sort_recursive( $item );
			}
		}
	}
}
