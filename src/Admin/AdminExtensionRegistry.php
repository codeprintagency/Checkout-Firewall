<?php
/**
 * Bounded presentation bridge for separately packaged extensions.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

final class AdminExtensionRegistry {
	private static ?AdminExtensionPresenter $presenter = null;
	/**
	 * Bounded presenter extensions.
	 *
	 * @var list<AdminExtensionPresenter>
	 */
	private static array $extensions = array();

	public static function assign( AdminExtensionPresenter $presenter ): bool {
		if ( null !== self::$presenter ) {
			return false;
		}
		self::$presenter = $presenter;
		return true;
	}

	public static function extend( AdminExtensionPresenter $presenter ): bool {
		if ( count( self::$extensions ) >= 2 ) {
			return false;
		}
		self::$extensions[] = $presenter;
		return true;
	}

	public static function render( string $view ): void {
		if ( null !== self::$presenter ) {
			self::$presenter->render( $view );
		}
		foreach ( self::$extensions as $extension ) {
			$extension->render( $view );
		}
	}

	public static function status_copy( string $status ): ?string {
		if ( null !== self::$presenter ) {
			$copy = self::$presenter->status_copy( $status );
			if ( null !== $copy ) {
				return $copy;
			}
		}
		foreach ( self::$extensions as $extension ) {
			$copy = $extension->status_copy( $status );
			if ( null !== $copy ) {
				return $copy;
			}
		}
		return null;
	}

	public static function license_label(): string {
		return null === self::$presenter ? '' : self::$presenter->license_label();
	}

	public static function privacy_policy_paragraph(): string {
		$paragraphs = array();
		if ( null !== self::$presenter ) {
			$paragraphs[] = self::$presenter->privacy_policy_paragraph();
		}
		foreach ( self::$extensions as $extension ) {
			$paragraphs[] = $extension->privacy_policy_paragraph();
		}
		return implode( ' ', array_filter( $paragraphs ) );
	}

	public static function clear_for_test(): void {
		self::$presenter  = null;
		self::$extensions = array();
	}
}
