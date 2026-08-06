<?php
/**
 * Bounded transient-failure circuit for remote challenge providers.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

final class ProviderRecovery {
	public const OPTION           = 'checkout_firewall_challenge_provider_recovery';
	public const COOLDOWN_SECONDS = 300;

	/**
	 * Current timestamp provider.
	 *
	 * @var \Closure():int
	 */
	private \Closure $clock;

	public function __construct( ?callable $clock = null ) {
		$this->clock = \Closure::fromCallable( $clock ?? 'time' );
	}

	public function record_unavailable( string $provider, string $classification ): void {
		if ( ! self::is_remote( $provider ) ) {
			return;
		}
		$now                = ( $this->clock )();
		$state              = $this->read();
		$state[ $provider ] = array(
			'format'         => 1,
			'classification' => substr( sanitize_key( $classification ), 0, 32 ),
			'retry_after'    => $now + self::COOLDOWN_SECONDS,
		);
		$this->write( $state );
	}

	public function clear( string $provider ): void {
		$state = $this->read();
		if ( ! isset( $state[ $provider ] ) ) {
			return;
		}
		unset( $state[ $provider ] );
		$this->write( $state );
	}

	public function can_attempt( string $provider ): bool {
		if ( ! self::is_remote( $provider ) ) {
			return true;
		}
		$state = $this->read();
		return ! isset( $state[ $provider ] ) || $state[ $provider ]['retry_after'] <= ( $this->clock )();
	}

	/**
	 * Read only the closed two-provider circuit schema.
	 *
	 * @return array<string,array{format:int,classification:string,retry_after:int}>
	 */
	private function read(): array {
		$value = get_option( self::OPTION, array() );
		if ( ! is_array( $value ) ) {
			return array();
		}
		$state = array();
		foreach ( array( ChallengeConfig::TURNSTILE, ChallengeConfig::RECAPTCHA ) as $provider ) {
			$entry = $value[ $provider ] ?? null;
			if ( is_array( $entry ) && 1 === ( $entry['format'] ?? null ) && is_string( $entry['classification'] ?? null )
				&& strlen( $entry['classification'] ) <= 32 && is_int( $entry['retry_after'] ?? null ) && $entry['retry_after'] >= 0
			) {
				$state[ $provider ] = $entry;
			}
		}
		return $state;
	}

	/**
	 * Persist the closed circuit state without autoloading it.
	 *
	 * @param array<string,array{format:int,classification:string,retry_after:int}> $state Circuit state.
	 */
	private function write( array $state ): void {
		if ( array() === $state ) {
			delete_option( self::OPTION );
			return;
		}
		if ( false === get_option( self::OPTION, false ) ) {
			add_option( self::OPTION, $state, '', false );
			return;
		}
		update_option( self::OPTION, $state, false );
	}

	private static function is_remote( string $provider ): bool {
		return in_array( $provider, array( ChallengeConfig::TURNSTILE, ChallengeConfig::RECAPTCHA ), true );
	}
}
