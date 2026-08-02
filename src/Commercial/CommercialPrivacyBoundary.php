<?php
/**
 * Freemius consent-permission minimization.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class CommercialPrivacyBoundary {
	private const PROHIBITED = array( 'site', 'diagnostic', 'extensions', 'newsletter' );
	private const SUFFIX     = '_checkout-firewall';

	/** Register supported SDK-scoped permission filters. */
	public static function register(): void {
		add_filter( 'fs_permission_list' . self::SUFFIX, array( self::class, 'filter_permissions' ) );
		add_filter( 'fs_permission_site_default' . self::SUFFIX, array( self::class, 'deny_default' ) );
		add_filter( 'fs_permission_diagnostic_default' . self::SUFFIX, array( self::class, 'deny_default' ) );
		add_filter( 'fs_permission_extensions_default' . self::SUFFIX, array( self::class, 'deny_default' ) );
		add_filter( 'fs_permission_newsletter_default' . self::SUFFIX, array( self::class, 'deny_default' ) );
		add_filter( 'fs_is_site_tracking_allowed' . self::SUFFIX, array( self::class, 'deny_default' ) );
		add_filter( 'fs_is_diagnostic_tracking_allowed' . self::SUFFIX, array( self::class, 'deny_default' ) );
		add_filter( 'fs_is_extensions_tracking_allowed' . self::SUFFIX, array( self::class, 'deny_default' ) );
	}

	/**
	 * Remove optional permissions outside the disclosed licensing boundary.
	 *
	 * @param array<mixed> $permissions Freemius permission descriptors.
	 * @return array<mixed>
	 */
	public static function filter_permissions( array $permissions ): array {
		return array_values(
			array_filter(
				$permissions,
				static function ( $permission ): bool {
					return ! is_array( $permission ) || ! in_array( $permission['id'] ?? null, self::PROHIBITED, true );
				}
			)
		);
	}

	/** Disable any SDK default for an optional prohibited permission. */
	public static function deny_default(): bool {
		return false;
	}
}
