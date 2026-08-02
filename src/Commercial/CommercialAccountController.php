<?php
/**
 * Explicit merchant-controlled Freemius connection action.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class CommercialAccountController {
	public const ACTION = 'cwf_connect_freemius';

	public function register(): void {
		add_action( 'admin_post_' . self::ACTION, array( $this, 'connect' ) );
	}

	public function connect(): void {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			wp_die( esc_html__( 'You are not allowed to connect Checkout Firewall licensing.', 'checkout-firewall' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );
		$sdk = CommercialBootstrap::sdk();
		if ( null !== $sdk && method_exists( $sdk, 'connect_again' ) ) {
			try {
				$sdk->connect_again();
			} catch ( \Throwable $exception ) {
				unset( $exception );
			}
		}
		wp_safe_redirect( admin_url( 'admin.php?page=checkout-firewall&view=privacy&cwf_status=licensing_unavailable' ) );
		exit;
	}
}
