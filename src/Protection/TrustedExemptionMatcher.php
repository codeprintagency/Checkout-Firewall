<?php
/**
 * Trusted-exemption request matcher.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Security\KeyStore;

final class TrustedExemptionMatcher {
	public function __construct( private TrustedExemptionStore $store, private ?ClientIpResolver $ips = null, private ?KeyStore $keys = null ) {
		$this->ips  = $ips ?? new ClientIpResolver();
		$this->keys = $keys ?? new KeyStore();
	}

	/**
	 * Match the current WordPress user or resolved visitor address.
	 *
	 * @return array<string,mixed>|null
	 */
	public function match(): ?array {
		$user_id = function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0;
		$ip      = $this->ips->resolve();
		$ip_key  = null;
		if ( null !== $ip ) {
			$ip_key = bin2hex( $this->keys->active_key( IdentifierType::IP, $ip )['active_key'] );
		}
		foreach ( $this->store->active() as $row ) {
			if ( 'user' === $row['subject_type'] && $user_id > 0 && $user_id === $row['user_id'] ) {
				return $row;
			}
			if ( null === $ip ) {
				continue;
			}
			if ( 'ip' === $row['subject_type'] && is_string( $ip_key ) && hash_equals( $row['active_key'], $ip_key ) ) {
				return $row;
			}
			if ( 'network' === $row['subject_type'] && self::in_network( $ip, $row['network'], $row['prefix'] ) ) {
				return $row;
			}
		}
		return null;
	}

	private static function in_network( string $ip, string $network, int $prefix ): bool {
		$address = inet_pton( $ip );
		$base    = inet_pton( $network );
		if ( false === $address || false === $base || strlen( $address ) !== strlen( $base ) ) {
			return false;
		}
		$bytes = intdiv( $prefix, 8 );
		$bits  = $prefix % 8;
		if ( substr( $address, 0, $bytes ) !== substr( $base, 0, $bytes ) ) {
			return false;
		}
		return 0 === $bits || ( ord( $address[ $bytes ] ) & ( 256 - ( 1 << ( 8 - $bits ) ) ) ) === ( ord( $base[ $bytes ] ) & ( 256 - ( 1 << ( 8 - $bits ) ) ) );
	}
}
