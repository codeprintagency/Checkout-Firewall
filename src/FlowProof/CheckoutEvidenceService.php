<?php
/**
 * Signed render-time and randomized honeypot evidence.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Security\KeyStore;

final class CheckoutEvidenceService {
	public const PREFIX    = 'cwfe1';
	public const MAX_TOKEN = 1024;
	public const TTL       = 300;
	public const MIN_AGE   = 1;
	private const CONTEXT  = 'checkout-firewall/checkout-evidence/sign/v1';

	private KeyStore $keys;
	/**
	 * Current timestamp provider.
	 *
	 * @var \Closure():int
	 */
	private \Closure $clock;
	/**
	 * Secure random-byte provider.
	 *
	 * @var \Closure(int):string
	 */
	private \Closure $random;

	public function __construct( ?KeyStore $keys = null, ?callable $clock = null, ?callable $random = null ) {
		$this->keys   = $keys ?? new KeyStore();
		$this->clock  = \Closure::fromCallable( $clock ?? 'time' );
		$this->random = \Closure::fromCallable( $random ?? 'random_bytes' );
	}

	/**
	 * Mint signed checkout evidence.
	 *
	 * @return array{evidence_token:string,honeypot_field:string,evidence_wait_ms:int}
	 * @throws \RuntimeException When evidence cannot be safely minted.
	 */
	public function mint( CartBinding $binding ): array {
		$now    = ( $this->clock )();
		$random = ( $this->random )( 8 );
		if ( 8 !== strlen( $random ) ) {
			throw new \RuntimeException( 'Checkout evidence entropy is unavailable.' );
		}
		$claims = array(
			'binding' => $this->binding( $binding ),
			'exp'     => $now + self::TTL,
			'field'   => 'cwf_hp_' . bin2hex( $random ),
			'iat'     => $now,
			'v'       => 1,
		);
		$json   = wp_json_encode( $claims, JSON_UNESCAPED_SLASHES );
		if ( ! is_string( $json ) ) {
			throw new \RuntimeException( 'Checkout evidence could not be encoded.' );
		}
		$body  = Base64Url::encode( $json );
		$token = self::PREFIX . '.' . $body . '.' . Base64Url::encode( hash_hmac( 'sha256', self::PREFIX . '.' . $body, $this->key(), true ) );
		if ( strlen( $token ) > self::MAX_TOKEN ) {
			throw new \RuntimeException( 'Checkout evidence exceeded its output bound.' );
		}
		return array(
			'evidence_token'   => $token,
			'honeypot_field'   => $claims['field'],
			'evidence_wait_ms' => self::MIN_AGE * 1000,
		);
	}

	/**
	 * Return neutral or one closed suspicious classification.
	 */
	public function classify( mixed $token, mixed $field, mixed $value, CartBinding $binding ): string {
		if ( null === $token && null === $field && null === $value ) {
			return '';
		}
		if ( ! is_string( $token ) || ! is_string( $field ) || ! is_string( $value ) || strlen( $token ) > self::MAX_TOKEN
			|| strlen( $field ) > 40 || strlen( $value ) > 256 || 1 !== preg_match( '/^cwf_hp_[a-f0-9]{16}$/D', $field )
		) {
			return 'evidence_malformed';
		}
		$parts = explode( '.', $token );
		if ( 3 !== count( $parts ) || self::PREFIX !== $parts[0] ) {
			return 'evidence_invalid';
		}
		try {
			$signature = Base64Url::decode( $parts[2] );
			$json      = Base64Url::decode( $parts[1] );
		} catch ( \Throwable $exception ) {
			return 'evidence_invalid';
		}
		$expected = hash_hmac( 'sha256', self::PREFIX . '.' . $parts[1], $this->key(), true );
		if ( 32 !== strlen( $signature ) || ! hash_equals( $expected, $signature ) ) {
			return 'evidence_invalid';
		}
		$claims = json_decode( $json, true );
		$now    = ( $this->clock )();
		if ( ! is_array( $claims ) || array( 'binding', 'exp', 'field', 'iat', 'v' ) !== array_keys( $claims )
			|| 1 !== ( $claims['v'] ?? null ) || ! is_int( $claims['iat'] ?? null ) || ! is_int( $claims['exp'] ?? null )
			|| ! is_string( $claims['field'] ?? null ) || ! is_string( $claims['binding'] ?? null )
			|| $claims['exp'] < $now || $claims['exp'] > $claims['iat'] + self::TTL || $claims['iat'] > $now + 30
			|| ! hash_equals( $claims['field'], $field ) || ! hash_equals( $claims['binding'], $this->binding( $binding ) )
		) {
			return 'evidence_invalid';
		}
		if ( '' !== $value ) {
			return 'honeypot_filled';
		}
		return $now - $claims['iat'] < self::MIN_AGE ? 'submitted_too_fast' : '';
	}

	private function binding( CartBinding $binding ): string {
		return hash_hmac( 'sha256', $binding->host() . "\0" . $binding->session_source() . "\0" . $binding->cart_source(), $this->key() );
	}

	private function key(): string {
		return $this->keys->derive_challenge_key( self::CONTEXT )['material'];
	}
}
