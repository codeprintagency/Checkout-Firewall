<?php
/**
 * Privacy-minimized operational display hints.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

use Codeprint\CheckoutFirewall\Data\IdentifierType;

final class IdentityMasker {
	public static function ip( string $value ): string {
		$packed = inet_pton( $value );
		if ( false === $packed ) {
			return '';
		}
		$canonical = inet_ntop( $packed );
		if ( false === $canonical ) {
			return '';
		}
		if ( 4 === strlen( $packed ) ) {
			$parts    = explode( '.', $canonical );
			$parts[3] = 'xxx';
			return implode( '.', $parts );
		}
		$parts = explode( ':', self::expand_ipv6( $packed ) );
		return implode( ':', array_merge( array_slice( $parts, 0, 3 ), array_fill( 0, 5, 'xxxx' ) ) );
	}

	public static function email( string $value ): string {
		$value = strtolower( trim( sanitize_email( $value ) ) );
		if ( '' === $value || strlen( $value ) > 254 || ! is_email( $value ) ) {
			return '';
		}
		$parts = explode( '@', $value, 2 );
		return substr( $parts[0], 0, 1 ) . '•••@' . $parts[1];
	}

	public static function label( int $type ): string {
		$labels = array(
			IdentifierType::IP       => __( 'IP identity', 'checkout-firewall' ),
			IdentifierType::EMAIL    => __( 'Email identity', 'checkout-firewall' ),
			IdentifierType::SESSION  => __( 'Session identity', 'checkout-firewall' ),
			IdentifierType::IP_EMAIL => __( 'Combined identity', 'checkout-firewall' ),
			IdentifierType::GATEWAY  => __( 'Gateway identity', 'checkout-firewall' ),
			IdentifierType::SITE     => __( 'Site identity', 'checkout-firewall' ),
		);
		return $labels[ $type ] ?? __( 'Local identity', 'checkout-firewall' );
	}

	private static function expand_ipv6( string $packed ): string {
		$groups = unpack( 'n8', $packed );
		return is_array( $groups ) ? implode( ':', array_map( static fn( int $group ): string => dechex( $group ), $groups ) ) : '';
	}
}
