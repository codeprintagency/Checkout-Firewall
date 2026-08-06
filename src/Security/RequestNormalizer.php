<?php
/**
 * Typed, sanitize-early request-boundary normalization.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Security;

final class RequestNormalizer {
	/**
	 * Read and normalize a POST string at the request boundary.
	 *
	 * @return array{value:?string,invalid:bool,present:bool}
	 */
	public static function post( string $key, int $maximum, ?string $pattern = null ): array {
		$present = array_key_exists( $key, $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Callers enforce the appropriate WooCommerce or admin nonce before use.
		$result  = self::text( $present ? $_POST[ $key ] : null, $maximum, true, $pattern ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- This is the single typed sanitize-early boundary; text() immediately type-checks, unslashes, sanitizes, bounds, and rejects changes.
		return $result + array( 'present' => $present );
	}

	/**
	 * Read and normalize a multiline POST string at the request boundary.
	 *
	 * @return array{value:?string,invalid:bool,present:bool}
	 */
	public static function post_textarea( string $key, int $maximum ): array {
		$present = array_key_exists( $key, $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Callers enforce the appropriate admin nonce before use.
		$value   = $present ? $_POST[ $key ] : null; // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- The following statements immediately type-check, unslash, sanitize, bound, and reject changes.
		if ( null === $value ) {
			return array(
				'value'   => null,
				'invalid' => false,
				'present' => false,
			);
		}
		if ( ! is_string( $value ) ) {
			return array(
				'value'   => null,
				'invalid' => true,
				'present' => true,
			);
		}
		$raw       = wp_unslash( $value );
		$sanitized = sanitize_textarea_field( $raw );
		$invalid   = $sanitized !== $raw || strlen( $sanitized ) > $maximum;
		return array(
			'value'   => $invalid ? null : $sanitized,
			'invalid' => $invalid,
			'present' => true,
		);
	}

	/**
	 * Read and normalize a query string at the request boundary.
	 *
	 * @return array{value:?string,invalid:bool,present:bool}
	 */
	public static function query( string $key, int $maximum, ?string $pattern = null ): array {
		$present = array_key_exists( $key, $_GET ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only query values are closed and normalized below.
		$result  = self::text( $present ? $_GET[ $key ] : null, $maximum, true, $pattern ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- This is the single typed sanitize-early boundary; text() immediately type-checks, unslashes, sanitizes, bounds, and rejects changes.
		return $result + array( 'present' => $present );
	}

	/**
	 * Read and normalize a server string at the request boundary.
	 *
	 * @return array{value:?string,invalid:bool,present:bool}
	 */
	public static function server( string $key, int $maximum, ?string $pattern = null ): array {
		$present = array_key_exists( $key, $_SERVER );
		$result  = self::text( $present ? $_SERVER[ $key ] : null, $maximum, true, $pattern ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- This is the single typed sanitize-early boundary; text() immediately type-checks, unslashes, sanitizes, bounds, and rejects changes.
		return $result + array( 'present' => $present );
	}

	/**
	 * Normalize a scalar string without silently rewriting signed material.
	 *
	 * @return array{value:?string,invalid:bool}
	 */
	public static function text( mixed $value, int $maximum, bool $slashed = true, ?string $pattern = null ): array {
		if ( null === $value ) {
			return array(
				'value'   => null,
				'invalid' => false,
			);
		}
		if ( ! is_string( $value ) ) {
			return array(
				'value'   => null,
				'invalid' => true,
			);
		}
		$raw       = $slashed ? wp_unslash( $value ) : $value;
		$sanitized = sanitize_text_field( $raw );
		$invalid   = $sanitized !== $raw || strlen( $sanitized ) > $maximum;
		if ( null !== $pattern && 1 !== preg_match( $pattern, $sanitized ) ) {
			$invalid = true;
		}
		return array(
			'value'   => $invalid ? null : $sanitized,
			'invalid' => $invalid,
		);
	}

	public static function method( mixed $value ): string {
		$normalized = self::text( $value, 16 );
		return $normalized['invalid'] || null === $normalized['value'] ? '' : strtoupper( $normalized['value'] );
	}

	public static function request_method(): string {
		$normalized = self::server( 'REQUEST_METHOD', 16, '/^[A-Za-z]+$/D' );
		return $normalized['invalid'] || null === $normalized['value'] ? '' : strtoupper( $normalized['value'] );
	}
}
