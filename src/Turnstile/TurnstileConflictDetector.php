<?php
/**
 * Detect known checkout-capable Turnstile plugin conflicts.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

final class TurnstileConflictDetector {
	private const KNOWN_SLUGS = array(
		'simple-cloudflare-turnstile',
		'empex-cloudflare-turnstile',
		'smart-captcha-alternative-with-cloudflare-turnstile',
	);

	/**
	 * Optional active-plugin test seam.
	 *
	 * @var list<string>|null
	 */
	private ?array $active_plugins;

	/**
	 * Create a detector with an optional deterministic active-plugin list.
	 *
	 * @param list<string>|null $active_plugins Optional deterministic test seam.
	 */
	public function __construct( ?array $active_plugins = null ) {
		$this->active_plugins = $active_plugins;
	}

	public function active_slug(): ?string {
		$known = apply_filters( 'checkout_firewall_turnstile_conflict_slugs', self::KNOWN_SLUGS );
		if ( ! is_array( $known ) ) {
			$known = self::KNOWN_SLUGS;
		}
		$known = array_slice( array_values( array_unique( array_map( 'sanitize_key', array_filter( $known, 'is_string' ) ) ) ), 0, 20 );

		foreach ( $this->plugins() as $plugin ) {
			$directory = strtok( $plugin, '/' );
			$slug      = sanitize_key( false === $directory ? '' : $directory );
			if ( in_array( $slug, $known, true ) ) {
				return $slug;
			}
		}
		return null;
	}

	public function has_conflict(): bool {
		return null !== $this->active_slug();
	}

	/**
	 * Read active site and network plugin basenames.
	 *
	 * @return list<string>
	 */
	private function plugins(): array {
		if ( null !== $this->active_plugins ) {
			return $this->active_plugins;
		}
		$plugins = get_option( 'active_plugins', array() );
		$plugins = is_array( $plugins ) ? array_values( array_filter( $plugins, 'is_string' ) ) : array();
		if ( is_multisite() ) {
			$network = get_site_option( 'active_sitewide_plugins', array() );
			if ( is_array( $network ) ) {
				$plugins = array_merge( $plugins, array_keys( $network ) );
			}
		}
		return $plugins;
	}
}
