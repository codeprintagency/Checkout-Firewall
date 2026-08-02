<?php
/**
 * Bounded Google reCAPTCHA Siteverify client.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Recaptcha;

use Codeprint\CheckoutFirewall\Turnstile\SiteverifyResult;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;

final class SiteverifyClient {
	public const ENDPOINT  = 'https://www.google.com/recaptcha/api/siteverify';
	public const MAX_TOKEN = 4096;
	public const MAX_BODY  = 16384;
	public const TIMEOUT   = 3.0;

	/**
	 * Optional HTTP transport seam.
	 *
	 * @var null|\Closure(string,array<string,mixed>):mixed
	 */
	private ?\Closure $transport;
	/**
	 * Current timestamp provider.
	 *
	 * @var \Closure():int
	 */
	private \Closure $clock;

	public function __construct( ?callable $transport = null, ?callable $clock = null ) {
		$this->transport = null === $transport ? null : \Closure::fromCallable( $transport );
		$this->clock     = \Closure::fromCallable( $clock ?? 'time' );
	}

	public function verify( string $token, string $secret, string $hostname ): SiteverifyResult {
		if ( '' === $token || strlen( $token ) > self::MAX_TOKEN || '' === $secret ) {
			return new SiteverifyResult( SiteverifyResult::INVALID, 'invalid_response' );
		}
		$args = array(
			'timeout'             => self::TIMEOUT,
			'redirection'         => 0,
			'reject_unsafe_urls'  => true,
			'sslverify'           => true,
			'limit_response_size' => self::MAX_BODY,
			'headers'             => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
			'body'                => array(
				'secret'   => $secret,
				'response' => $token,
			),
		);
		try {
			$response = null === $this->transport ? wp_remote_post( self::ENDPOINT, $args ) : ( $this->transport )( self::ENDPOINT, $args );
		} catch ( \Throwable $exception ) {
			return new SiteverifyResult( SiteverifyResult::UNAVAILABLE, 'transport_error' );
		}
		if ( is_wp_error( $response ) ) {
			return new SiteverifyResult( SiteverifyResult::UNAVAILABLE, 'transport_error' );
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		if ( 200 !== $code || ! is_string( $body ) || '' === $body || strlen( $body ) > self::MAX_BODY ) {
			return new SiteverifyResult( SiteverifyResult::UNAVAILABLE, 'http_error' );
		}
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) || ! array_key_exists( 'success', $data ) || ! is_bool( $data['success'] ) ) {
			return new SiteverifyResult( SiteverifyResult::UNAVAILABLE, 'malformed_response' );
		}
		if ( false === $data['success'] ) {
			$codes = isset( $data['error-codes'] ) && is_array( $data['error-codes'] ) ? array_slice( $data['error-codes'], 0, 16 ) : array();
			if ( in_array( 'invalid-input-secret', $codes, true ) || in_array( 'missing-input-secret', $codes, true ) ) {
				return new SiteverifyResult( SiteverifyResult::INVALID_SECRET, 'invalid_secret' );
			}
			return new SiteverifyResult( SiteverifyResult::INVALID, in_array( 'timeout-or-duplicate', $codes, true ) ? 'timeout_or_duplicate' : 'invalid_response' );
		}
		$response_host = isset( $data['hostname'] ) && is_string( $data['hostname'] ) ? TurnstileConfig::hostname( $data['hostname'] ) : '';
		$timestamp     = isset( $data['challenge_ts'] ) && is_string( $data['challenge_ts'] ) ? strtotime( $data['challenge_ts'] ) : false;
		$now           = ( $this->clock )();
		if ( '' === $response_host || ! hash_equals( TurnstileConfig::hostname( $hostname ), $response_host )
			|| false === $timestamp || $timestamp < $now - 300 || $timestamp > $now + 30
		) {
			return new SiteverifyResult( SiteverifyResult::INVALID, 'context_mismatch' );
		}
		return new SiteverifyResult( SiteverifyResult::VALID, 'valid' );
	}
}
