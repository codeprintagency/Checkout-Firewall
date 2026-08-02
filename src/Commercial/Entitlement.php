<?php
/**
 * Immutable closed commercial entitlement value.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class Entitlement {
	public const FREE           = 'free';
	public const ACTIVE_PAID    = 'active_paid';
	public const EXPIRED        = 'expired';
	public const CANCELLED      = 'cancelled';
	public const INVALID        = 'invalid';
	public const MISSING        = 'missing';
	public const UNCONFIGURED   = 'unconfigured';
	public const PROVIDER_ERROR = 'provider_error';

	private string $code_type;
	private string $state;
	private string $plan;
	private bool $premium_allowed;

	public function __construct( string $code_type, string $state, string $plan, bool $premium_allowed ) {
		$this->code_type       = CodeType::normalize( $code_type );
		$this->state           = $state;
		$this->plan            = $plan;
		$this->premium_allowed = $premium_allowed;
	}

	public static function free( string $state = self::FREE ): self {
		return new self( CodeType::FREE, $state, '', false );
	}

	public function code_type(): string {
		return $this->code_type;
	}

	public function state(): string {
		return $this->state;
	}

	public function plan(): string {
		return $this->plan;
	}

	public function allows_premium(): bool {
		return $this->premium_allowed;
	}
}
