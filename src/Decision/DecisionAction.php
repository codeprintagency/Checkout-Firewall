<?php
/**
 * Checkout decision action registry.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Decision;

final class DecisionAction {
	public const ALLOW     = 'allow';
	public const CHALLENGE = 'challenge';
	public const BLOCK     = 'block';

	/**
	 * Return every supported action.
	 *
	 * @return list<string>
	 */
	public static function all(): array {
		return array( self::ALLOW, self::CHALLENGE, self::BLOCK );
	}

	public static function rank( string $action ): int {
		$rank = array(
			self::ALLOW     => 0,
			self::CHALLENGE => 1,
			self::BLOCK     => 2,
		);

		if ( ! isset( $rank[ $action ] ) ) {
			throw new \InvalidArgumentException( 'Unknown checkout decision action.' );
		}

		return $rank[ $action ];
	}
}
