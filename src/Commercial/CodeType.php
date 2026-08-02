<?php
/**
 * Closed generated-package code types.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class CodeType {
	public const FREE    = 'free';
	public const PREMIUM = 'premium';

	public static function normalize( string $value ): string {
		return self::PREMIUM === $value ? self::PREMIUM : self::FREE;
	}
}
