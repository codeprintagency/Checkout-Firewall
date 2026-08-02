<?php
/**
 * Canonical unpadded Base64URL codec.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

final class Base64Url {
	public static function encode( string $binary ): string {
		return rtrim( strtr( base64_encode( $binary ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Token binary transport, not obfuscation.
	}

	public static function decode( string $encoded ): string {
		if ( '' === $encoded || 1 !== preg_match( '/^[A-Za-z0-9_-]+$/D', $encoded ) || 1 === strlen( $encoded ) % 4 ) {
			throw new InvalidProofException();
		}

		$padding = ( 4 - ( strlen( $encoded ) % 4 ) ) % 4;
		$decoded = base64_decode( strtr( $encoded, '-_', '+/' ) . str_repeat( '=', $padding ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Token binary transport, not obfuscation.
		if ( false === $decoded || ! hash_equals( $encoded, self::encode( $decoded ) ) ) {
			throw new InvalidProofException();
		}

		return $decoded;
	}
}
