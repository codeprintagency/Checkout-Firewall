<?php
/**
 * Authorized support-snapshot download.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

final class SupportExportController {
	public const ACTION    = 'cwf_download_support_snapshot';
	public const MAX_BYTES = 65536;

	public function register(): void {
		add_action( 'admin_post_' . self::ACTION, array( $this, 'download' ) );
	}

	public function download(): void {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'POST' !== $method || ! current_user_can( 'manage_woocommerce' ) ) {
			wp_die( esc_html__( 'You are not allowed to download this snapshot.', 'checkout-firewall' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		try {
			$json = wp_json_encode( ( new SupportSnapshot() )->build(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		} catch ( \Throwable $exception ) {
			unset( $exception );
			$json = false;
		}
		if ( ! is_string( $json ) || strlen( $json ) + 1 > self::MAX_BYTES ) {
			wp_die( esc_html__( 'The support snapshot could not be generated safely.', 'checkout-firewall' ), '', array( 'response' => 500 ) );
		}

		nocache_headers();
		header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0', true );
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="checkout-firewall-support.json"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo $json . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Closed JSON attachment.
		exit;
	}
}
