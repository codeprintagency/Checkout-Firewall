<?php
/**
 * Bounded Siteverify outcome.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

final class SiteverifyResult {
	public const VALID          = 'valid';
	public const INVALID        = 'invalid';
	public const INVALID_SECRET = 'invalid_secret';
	public const UNAVAILABLE    = 'unavailable';

	private string $status;
	private string $classification;

	public function __construct( string $status, string $classification = '' ) {
		if ( ! in_array( $status, array( self::VALID, self::INVALID, self::INVALID_SECRET, self::UNAVAILABLE ), true ) ) {
			throw new \InvalidArgumentException( 'Invalid Siteverify result.' );
		}
		$this->status         = $status;
		$this->classification = substr( preg_replace( '/[^a-z0-9_]/', '', strtolower( $classification ) ) ?? '', 0, 32 );
	}

	public function status(): string {
		return $this->status;
	}

	public function classification(): string {
		return $this->classification;
	}

	public function is_valid(): bool {
		return self::VALID === $this->status;
	}
}
