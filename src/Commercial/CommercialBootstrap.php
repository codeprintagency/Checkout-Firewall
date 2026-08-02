<?php
/**
 * Contained early Freemius initialization boundary.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

use Codeprint\CheckoutFirewall\Premium\FreemiusUninstallBridge;

final class CommercialBootstrap {
	private static ?FreemiusConfig $config        = null;
	private static ?EntitlementProvider $provider = null;
	private static ?object $sdk                   = null;

	public static function initialize( string $project_directory ): void {
		self::$config   = FreemiusConfig::load( $project_directory );
		self::$provider = new FreeEntitlementProvider( Entitlement::UNCONFIGURED );
		self::$sdk      = null;

		if ( ! self::$config->is_configured() ) {
			return;
		}

		try {
			CommercialPrivacyBoundary::register();
			$sdk_file = rtrim( $project_directory, '/\\' ) . '/vendor/freemius/wordpress-sdk/start.php';
			if ( ! is_readable( $sdk_file ) ) {
				self::$provider = new FreeEntitlementProvider( Entitlement::PROVIDER_ERROR );
				return;
			}
			require_once $sdk_file;
			if ( ! function_exists( 'fs_dynamic_init' ) ) {
				self::$provider = new FreeEntitlementProvider( Entitlement::PROVIDER_ERROR );
				return;
			}
			$sdk = fs_dynamic_init( array (
  'id' => 36328,
  'slug' => 'checkout-firewall',
  'premium_slug' => 'checkout-firewall-premium',
  'type' => 'plugin',
  'public_key' => 'pk_3c42b00c5aac89cd5bd09e009bff9',
  'is_premium' => false,
  'has_premium_version' => true,
  'has_paid_plans' => true,
  'is_org_compliant' => true,
  'anonymous_mode' => true,
  'has_affiliation' => false,
  'permissions' => 
  array (
    'newsletter' => false,
    'diagnostic' => false,
    'extensions' => false,
  ),
  'menu' => 
  array (
    'slug' => 'checkout-firewall',
    'first-path' => 'admin.php?page=checkout-firewall',
    'parent' => 
    array (
      'slug' => 'woocommerce',
    ),
  ),
) );
			if ( ! is_object( $sdk ) ) {
				self::$provider = new FreeEntitlementProvider( Entitlement::PROVIDER_ERROR );
				return;
			}
			$provider = new FreemiusEntitlementProvider( $sdk, self::$config->code_type(), self::$config->plans() );
			CommercialMenuBoundary::register( $sdk );
			CommercialUpgradePage::register( $sdk, $provider );
			if ( CodeType::PREMIUM === self::$config->code_type() && class_exists( FreemiusUninstallBridge::class ) ) {
				FreemiusUninstallBridge::register( $sdk );
			}
			self::$sdk      = $sdk;
			self::$provider = $provider;
		} catch ( \Throwable $exception ) {
			unset( $exception );
			self::$provider = new FreeEntitlementProvider( Entitlement::PROVIDER_ERROR );
		}
	}

	public static function provider(): EntitlementProvider {
		return self::$provider ?? new FreeEntitlementProvider( Entitlement::UNCONFIGURED );
	}

	public static function config(): FreemiusConfig {
		return self::$config ?? new FreemiusConfig( array() );
	}

	public static function sdk(): ?object {
		return self::$sdk;
	}

	public static function reset_for_test(): void {
		self::$config   = null;
		self::$provider = null;
		self::$sdk      = null;
		if ( class_exists( FreemiusUninstallBridge::class ) ) {
			FreemiusUninstallBridge::reset_for_test();
		}
	}
}
