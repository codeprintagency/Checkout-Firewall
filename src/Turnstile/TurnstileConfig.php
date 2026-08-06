<?php
/**
 * Validated, health-gated Turnstile configuration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

use Codeprint\CheckoutFirewall\Security\KeyStore;

final class TurnstileConfig {
	public const SITE_OPTION         = 'checkout_firewall_turnstile_site_key';
	public const SECRET_OPTION       = 'checkout_firewall_turnstile_secret_key';
	public const ENABLED_OPTION      = 'checkout_firewall_turnstile_enabled';
	public const VERIFICATION_OPTION = 'checkout_firewall_turnstile_verification';
	public const CONFIG_CONTEXT      = 'checkout-firewall/turnstile/config/v1';

	private KeyStore $keys;

	public function __construct( ?KeyStore $keys = null ) {
		$this->keys = $keys ?? new KeyStore();
	}

	/**
	 * Return the resolved key pair.
	 *
	 * @return array{site_key:string,secret_key:string}
	 */
	public function credentials(): array {
		$site   = defined( 'CHECKOUT_FIREWALL_TURNSTILE_SITE_KEY' ) ? CHECKOUT_FIREWALL_TURNSTILE_SITE_KEY : get_option( self::SITE_OPTION, '' );
		$secret = defined( 'CHECKOUT_FIREWALL_TURNSTILE_SECRET_KEY' ) ? CHECKOUT_FIREWALL_TURNSTILE_SECRET_KEY : get_option( self::SECRET_OPTION, '' );
		return array(
			'site_key'   => self::normalize( $site, 128 ),
			'secret_key' => self::normalize( $secret, 256 ),
		);
	}

	public function is_active(): bool {
		$credentials = $this->credentials();
		if ( '' === $credentials['site_key'] || '' === $credentials['secret_key'] || ! self::truthy( get_option( self::ENABLED_OPTION, false ) )
			|| ( self::is_test_pair( $credentials ) && ! self::test_keys_allowed() )
		) {
			return false;
		}

		$verification = get_option( self::VERIFICATION_OPTION, array() );
		if ( ! is_array( $verification ) || 1 !== (int) ( $verification['format'] ?? 0 ) ) {
			return false;
		}

		$fingerprint   = $verification['fingerprint'] ?? null;
		$verified_host = is_string( $verification['hostname'] ?? null ) ? self::hostname( $verification['hostname'] ) : '';
		return is_string( $fingerprint ) && 64 === strlen( $fingerprint )
			&& hash_equals( $fingerprint, $this->fingerprint( $credentials ) )
			&& '' !== $verified_host && hash_equals( $verified_host, self::current_hostname() );
	}

	/**
	 * Mark the current pair verified and optionally active.
	 *
	 * @throws \RuntimeException When credentials cannot be activated.
	 */
	public function verify( string $hostname, bool $enable = true ): void {
		$credentials = $this->credentials();
		if ( '' === $credentials['site_key'] || '' === $credentials['secret_key'] ) {
			throw new \RuntimeException( 'Turnstile credentials are incomplete.' );
		}
		if ( self::is_test_pair( $credentials ) && ! self::test_keys_allowed() ) {
			throw new \RuntimeException( 'Cloudflare test credentials cannot be activated in this environment.' );
		}
		self::write_option(
			self::VERIFICATION_OPTION,
			array(
				'format'          => 1,
				'fingerprint'     => $this->fingerprint( $credentials ),
				'hostname'        => self::hostname( $hostname ),
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

	/**
	 * Persist a bounded draft pair and invalidate prior health.
	 *
	 * @throws \InvalidArgumentException When either supplied key is invalid.
	 */
	public function save( string $site_key, ?string $secret_key ): void {
		$site_key = defined( 'CHECKOUT_FIREWALL_TURNSTILE_SITE_KEY' ) ? self::normalize( CHECKOUT_FIREWALL_TURNSTILE_SITE_KEY, 128 ) : self::normalize( $site_key, 128 );
		if ( '' === $site_key ) {
			throw new \InvalidArgumentException( 'Turnstile site key is invalid.' );
		}
		$normalized_secret = null;
		if ( ! defined( 'CHECKOUT_FIREWALL_TURNSTILE_SECRET_KEY' ) && null !== $secret_key && '' !== trim( $secret_key ) ) {
			$normalized_secret = self::normalize( $secret_key, 256 );
			if ( '' === $normalized_secret ) {
				throw new \InvalidArgumentException( 'Turnstile secret key is invalid.' );
			}
		}
		if ( ! defined( 'CHECKOUT_FIREWALL_TURNSTILE_SITE_KEY' ) ) {
			self::write_option( self::SITE_OPTION, $site_key );
		}
		if ( null !== $normalized_secret ) {
			self::write_option( self::SECRET_OPTION, $normalized_secret );
		}
		$this->invalidate();
	}

	public function remove(): void {
		delete_option( self::SITE_OPTION );
		delete_option( self::SECRET_OPTION );
		delete_option( self::ENABLED_OPTION );
		delete_option( self::VERIFICATION_OPTION );
	}

	public static function hostname( string $hostname ): string {
		$hostname = strtolower( rtrim( trim( $hostname ), '.' ) );
		if ( '' === $hostname || strlen( $hostname ) > 253 || 1 !== preg_match( '/^[a-z0-9.-]+$/D', $hostname ) ) {
			return '';
		}
		return $hostname;
	}

	public static function current_hostname(): string {
		$hostname = wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		return is_string( $hostname ) ? self::hostname( $hostname ) : '';
	}

	/**
	 * Determine whether either credential is an official Cloudflare test key.
	 *
	 * @param array{site_key:string,secret_key:string} $credentials Key pair.
	 */
	public static function is_test_pair( array $credentials ): bool {
		return in_array( $credentials['site_key'], array( '1x00000000000000000000AA', '2x00000000000000000000AB', '1x00000000000000000000BB', '2x00000000000000000000BB', '3x00000000000000000000FF' ), true )
			|| in_array( $credentials['secret_key'], array( '1x0000000000000000000000000000000AA', '2x0000000000000000000000000000000AA', '3x0000000000000000000000000000000AA' ), true );
	}

	/**
	 * Determine whether official test credentials are allowed here.
	 */
	public static function test_keys_allowed(): bool {
		$environment = function_exists( 'wp_get_environment_type' ) ? wp_get_environment_type() : 'production';
		return in_array( $environment, array( 'local', 'development', 'test' ), true );
	}

	/**
	 * Create a public cData value for the admin health widget.
	 *
	 * @return string
	 */
	public function health_cdata(): string {
		$credentials = $this->credentials();
		$key         = $this->keys->derive_turnstile_key( self::CONFIG_CONTEXT );
		return substr( \Codeprint\CheckoutFirewall\FlowProof\Base64Url::encode( hash_hmac( 'sha256', "health\0" . $credentials['site_key'], $key['material'], true ) ), 0, 43 );
	}

	/**
	 * Read the canonical hostname associated with current verification.
	 */
	public function verified_hostname(): string {
		$value = get_option( self::VERIFICATION_OPTION, array() );
		return is_array( $value ) && is_string( $value['hostname'] ?? null ) ? self::hostname( $value['hostname'] ) : '';
	}

	/**
	 * Fingerprint credentials without retaining an additional secret copy.
	 *
	 * @param array{site_key:string,secret_key:string} $credentials Key pair.
	 */
	private function fingerprint( array $credentials ): string {
		$key = $this->keys->derive_turnstile_key( self::CONFIG_CONTEXT );
		return hash_hmac( 'sha256', $credentials['site_key'] . "\0" . $credentials['secret_key'], $key['material'] );
	}

	/**
	 * Normalize an untrusted scalar credential.
	 *
	 * @param mixed $value Untrusted option/constant.
	 */
	private static function normalize( $value, int $limit ): string {
		if ( ! is_string( $value ) ) {
			return '';
		}
		$value = trim( $value );
		if ( '' === $value || strlen( $value ) > $limit || 1 === preg_match( '/[\x00-\x1F\x7F]/D', $value ) ) {
			return '';
		}
		return $value;
	}

	/**
	 * Interpret the closed activation option values.
	 *
	 * @param mixed $value Stored value.
	 */
	private static function truthy( $value ): bool {
		return true === $value || 1 === $value || '1' === $value || 'yes' === $value;
	}

	/**
	 * Write one non-autoloaded option.
	 *
	 * @param mixed $value Option value.
	 */
	private static function write_option( string $name, $value ): void {
		if ( false === get_option( $name, false ) ) {
			add_option( $name, $value, '', false );
			return;
		}
		update_option( $name, $value, false );
	}
}
