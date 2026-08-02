<?php
/**
 * Selected checkout challenge provider and safe local fallback policy.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

use Codeprint\CheckoutFirewall\Recaptcha\RecaptchaConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConflictDetector;

final class ChallengeConfig {
	public const OPTION    = 'cwf_challenge_provider';
	public const LOCAL     = 'local';
	public const TURNSTILE = 'turnstile';
	public const RECAPTCHA = 'recaptcha';
	public const NONE      = 'none';
	public const PROVIDERS = array( self::LOCAL, self::TURNSTILE, self::RECAPTCHA, self::NONE );

	private TurnstileConfig $turnstile;
	private RecaptchaConfig $recaptcha;
	private TurnstileConflictDetector $conflicts;
	private ?string $legacy_provider;
	private ProviderRecovery $recovery;

	public function __construct(
		?TurnstileConfig $turnstile = null,
		?RecaptchaConfig $recaptcha = null,
		?TurnstileConflictDetector $conflicts = null,
		?string $legacy_provider = null,
		?ProviderRecovery $recovery = null
	) {
		$this->turnstile       = $turnstile ?? new TurnstileConfig();
		$this->recaptcha       = $recaptcha ?? new RecaptchaConfig();
		$this->conflicts       = $conflicts ?? new TurnstileConflictDetector();
		$this->legacy_provider = in_array( $legacy_provider, self::PROVIDERS, true ) ? $legacy_provider : null;
		$this->recovery        = $recovery ?? new ProviderRecovery();
	}

	public function selected(): string {
		$value = get_option( self::OPTION, null );
		if ( is_string( $value ) && in_array( $value, self::PROVIDERS, true ) ) {
			return $value;
		}
		return $this->legacy_provider ?? ( $this->turnstile->is_active() ? self::TURNSTILE : self::LOCAL );
	}

	/**
	 * Return the provider that can safely serve a challenge now.
	 *
	 * Remote provider failure falls back to the local provider. An explicit
	 * `none` selection and a detected competing checkout CAPTCHA do not.
	 */
	public function effective(): string {
		$selected = $this->selected();
		if ( self::NONE === $selected || $this->conflicts->has_conflict() ) {
			return self::NONE;
		}
		if ( self::TURNSTILE === $selected && $this->turnstile->is_active() && $this->recovery->can_attempt( self::TURNSTILE ) ) {
			return self::TURNSTILE;
		}
		if ( self::RECAPTCHA === $selected && $this->recaptcha->is_active() && $this->recovery->can_attempt( self::RECAPTCHA ) ) {
			return self::RECAPTCHA;
		}
		return self::LOCAL;
	}

	public function is_available(): bool {
		return self::NONE !== $this->effective();
	}

	public function is_fallback(): bool {
		return $this->effective() !== $this->selected() && self::NONE !== $this->selected();
	}

	/**
	 * Keep an already-issued fallback stable while invalidating provider changes.
	 */
	public function accepts_pending( string $provider, string $selected_at_issue ): bool {
		$selected = $this->selected();
		if ( $this->conflicts->has_conflict() || self::NONE === $selected || ! hash_equals( $selected, $selected_at_issue ) ) {
			return false;
		}
		if ( self::LOCAL === $provider ) {
			return in_array( $selected, array( self::LOCAL, self::TURNSTILE, self::RECAPTCHA ), true );
		}
		if ( self::TURNSTILE === $provider ) {
			return self::TURNSTILE === $selected && $this->turnstile->is_active() && $this->recovery->can_attempt( self::TURNSTILE );
		}
		if ( self::RECAPTCHA === $provider ) {
			return self::RECAPTCHA === $selected && $this->recaptcha->is_active() && $this->recovery->can_attempt( self::RECAPTCHA );
		}
		return false;
	}

	public function select( string $provider ): void {
		if ( ! in_array( $provider, self::PROVIDERS, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported checkout challenge provider.' );
		}
		self::write_option( self::OPTION, $provider );
	}

	public function turnstile(): TurnstileConfig {
		return $this->turnstile;
	}

	public function recaptcha(): RecaptchaConfig {
		return $this->recaptcha;
	}

	public function conflicts(): TurnstileConflictDetector {
		return $this->conflicts;
	}

	public function recovery(): ProviderRecovery {
		return $this->recovery;
	}

	/**
	 * Persist one non-autoloaded provider choice.
	 */
	private static function write_option( string $name, string $value ): void {
		if ( false === get_option( $name, false ) ) {
			add_option( $name, $value, '', false );
			return;
		}
		update_option( $name, $value, false );
	}
}
