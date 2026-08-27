<?php
/**
 * Validated Google reCAPTCHA v2 checkbox configuration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Recaptcha;

use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;

final class RecaptchaConfig {
	public const SITE_OPTION         = 'checkout_firewall_recaptcha_site_key';
	public const SECRET_OPTION       = 'checkout_firewall_recaptcha_secret_key';
	public const ENABLED_OPTION      = 'checkout_firewall_recaptcha_enabled';
	public const VERIFICATION_OPTION = 'checkout_firewall_recaptcha_verification';
	public const CONFIG_CONTEXT      = 'checkout-firewall/challenge/recaptcha-config/v1';

	private KeyStore $keys;

	public function __construct( ?KeyStore $keys = null ) {
		$this->keys = $keys ?? new KeyStore();
	}

	/**
	 * Read normalized reCAPTCHA credentials.
	 *
	 * @return array{site_key:string,secret_key:string}
	 */
	public function credentials(): array {
		$site   = defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SITE_KEY' ) ? CHECKOUT_FIREWALL_RECAPTCHA_SITE_KEY : get_option( self::SITE_OPTION, '' );
		$secret = defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SECRET_KEY' ) ? CHECKOUT_FIREWALL_RECAPTCHA_SECRET_KEY : get_option( self::SECRET_OPTION, '' );
		return array(
			'site_key'   => self::normalize( $site, 128 ),
			'secret_key' => self::normalize( $secret, 256 ),
		);
	}

	public function is_active(): bool {
		$credentials = $this->credentials();
		if ( '' === $credentials['site_key'] || '' === $credentials['secret_key'] || ! self::truthy( get_option( self::ENABLED_OPTION, false ) ) ) {
			return false;
		}
		$verification = get_option( self::VERIFICATION_OPTION, array() );
		if ( ! is_array( $verification ) || 1 !== (int) ( $verification['format'] ?? 0 ) ) {
			return false;
		}
		$fingerprint = $verification['fingerprint'] ?? null;
		$hostname    = is_string( $verification['hostname'] ?? null ) ? TurnstileConfig::hostname( $verification['hostname'] ) : '';
		return is_string( $fingerprint ) && 64 === strlen( $fingerprint )
			&& hash_equals( $fingerprint, $this->fingerprint( $credentials ) )
			&& '' !== $hostname && hash_equals( $hostname, TurnstileConfig::current_hostname() );
	}

	public function save( string $site_key, ?string $secret_key ): void {
		$current  = $this->credentials();
		$site_key = defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SITE_KEY' ) ? self::normalize( CHECKOUT_FIREWALL_RECAPTCHA_SITE_KEY, 128 ) : self::normalize( $site_key, 128 );
		if ( '' === $site_key ) {
			throw new \InvalidArgumentException( 'reCAPTCHA site key is invalid.' );
		}
		$secret = defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SECRET_KEY' ) ? $current['secret_key'] : null;
		if ( ! defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SECRET_KEY' ) && null !== $secret_key && '' !== trim( $secret_key ) ) {
			$secret = self::normalize( $secret_key, 256 );
			if ( '' === $secret ) {
				throw new \InvalidArgumentException( 'reCAPTCHA secret key is invalid.' );
			}
		}
		$effective_secret = null === $secret ? $current['secret_key'] : $secret;
		if ( '' === $effective_secret ) {
			throw new \InvalidArgumentException( 'reCAPTCHA credentials are incomplete.' );
		}
		if ( ! defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SITE_KEY' ) ) {
			self::write_option( self::SITE_OPTION, $site_key );
		}
		if ( ! defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SECRET_KEY' ) && null !== $secret ) {
			self::write_option( self::SECRET_OPTION, $secret );
		}
		$stored = $this->credentials();
		if ( ! hash_equals( $site_key, $stored['site_key'] ) || ! hash_equals( $effective_secret, $stored['secret_key'] ) ) {
			throw new \RuntimeException( 'reCAPTCHA credentials could not be persisted.' );
		}
		$this->invalidate();
	}

	public function verify( string $hostname, bool $enable = true ): void {
		$credentials = $this->credentials();
		if ( '' === $credentials['site_key'] || '' === $credentials['secret_key'] ) {
			throw new \RuntimeException( 'reCAPTCHA credentials are incomplete.' );
		}
		self::write_option(
			self::VERIFICATION_OPTION,
			array(
				'format'          => 1,
				'fingerprint'     => $this->fingerprint( $credentials ),
				'hostname'        => TurnstileConfig::hostname( $hostname ),
				'verified_at_gmt' => gmdate( 'Y-m-d H:i:s' ),
			)
		);
		self::write_option( self::ENABLED_OPTION, $enable ? '1' : '0' );
	}

	public function disable(): void {
		self::write_option( self::ENABLED_OPTION, '0' );
	}

	public function invalidate(): void {
		$this->disable();
		delete_option( self::VERIFICATION_OPTION );
	}

	public function remove(): void {
		delete_option( self::SITE_OPTION );
		delete_option( self::SECRET_OPTION );
		delete_option( self::ENABLED_OPTION );
		delete_option( self::VERIFICATION_OPTION );
	}

	/**
	 * Derive a local credential fingerprint.
	 *
	 * @param array{site_key:string,secret_key:string} $credentials Credentials.
	 */
	private function fingerprint( array $credentials ): string {
		$key = $this->keys->derive_challenge_key( self::CONFIG_CONTEXT );
		return hash_hmac( 'sha256', $credentials['site_key'] . "\0" . $credentials['secret_key'], $key['material'] );
	}

	private static function normalize( mixed $value, int $limit ): string {
		if ( ! is_string( $value ) ) {
			return '';
		}
		$value = trim( $value );
		return '' !== $value && strlen( $value ) <= $limit && 1 !== preg_match( '/[\x00-\x1F\x7F]/D', $value ) ? $value : '';
	}

	private static function truthy( mixed $value ): bool {
		return true === $value || 1 === $value || '1' === $value || 'yes' === $value;
	}

	private static function write_option( string $name, mixed $value ): void {
		if ( false === get_option( $name, false ) ) {
			add_option( $name, $value, '', false );
			return;
		}
		update_option( $name, $value, false );
	}
}
