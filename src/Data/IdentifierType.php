<?php
/**
 * Append-only identifier type registry.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Data;

final class IdentifierType {
	public const IP       = 1;
	public const EMAIL    = 2;
	public const SESSION  = 3;
	public const IP_EMAIL = 4;
	public const GATEWAY  = 5;
	public const SITE     = 6;

	/**
	 * Return every registered identifier type.
	 *
	 * @return list<int>
	 */
	public static function all(): array {
		return array( self::IP, self::EMAIL, self::SESSION, self::IP_EMAIL, self::GATEWAY, self::SITE );
	}

	public static function is_valid( int $type ): bool {
		return in_array( $type, self::all(), true );
	}
}
