<?php
/**
 * Frozen M4 Free policy constants and calculations.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Data\IdentifierType;

final class ProtectionPolicy {
	public const BUCKET_SECONDS = 60;
	public const DECLINE_WINDOW = 900;
	public const OTHER_WINDOW   = 900;
	public const DECLINE_LIMIT  = 3;
	public const OTHER_LIMIT    = 5;
	public const DECLINE_LOCK   = 1800;
	public const OTHER_LOCK     = 900;
	public const OUTAGE_WINDOW  = 300;
	public const OUTAGE_MINIMUM = 20;
	public const OUTAGE_FAILURE = 16;

	/**
	 * Return the adaptive challenge policy for an identity.
	 *
	 * @return array{window:int,threshold:int}
	 * @throws \InvalidArgumentException When the identity type is unsupported.
	 */
	public static function velocity( int $type, bool $trusted ): array {
		$policies = array(
			IdentifierType::IP       => array( 300, 10 ),
			IdentifierType::EMAIL    => array( 900, 5 ),
			IdentifierType::SESSION  => array( 600, 3 ),
			IdentifierType::IP_EMAIL => array( 900, 3 ),
		);
		if ( ! isset( $policies[ $type ] ) ) {
			throw new \InvalidArgumentException( 'Unsupported velocity identity.' );
		}
		return array(
			'window'    => $policies[ $type ][0],
			'threshold' => $policies[ $type ][1] * ( $trusted ? 2 : 1 ),
		);
	}

	/**
	 * Return the temporary-throttle policy for an identity.
	 *
	 * @return array{window:int,threshold:int}
	 * @throws \InvalidArgumentException When the identity type is unsupported.
	 */
	public static function throttle( int $type, bool $trusted ): array {
		$policies = array(
			IdentifierType::IP       => array( 900, 30 ),
			IdentifierType::EMAIL    => array( 1800, 8 ),
			IdentifierType::SESSION  => array( 900, 6 ),
			IdentifierType::IP_EMAIL => array( 1800, 6 ),
		);
		if ( ! isset( $policies[ $type ] ) ) {
			throw new \InvalidArgumentException( 'Unsupported velocity identity.' );
		}
		return array(
			'window'    => $policies[ $type ][0],
			'threshold' => $policies[ $type ][1] * ( $trusted ? 2 : 1 ),
		);
	}

	public static function effective( int $risk, int $success, int $credit ): int {
		return max( 0, $risk - ( $success * $credit ) );
	}

	public static function outage( int $success, int $decline, int $other ): bool {
		$failures = $decline + $other;
		$total    = $success + $failures;
		return $total >= self::OUTAGE_MINIMUM
			&& $failures >= self::OUTAGE_FAILURE
			&& ( $failures * 100 ) >= ( $total * 80 );
	}
}
