<?php
/**
 * Capability-scoped dismissible Free incident notice.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Security\RequestNormalizer;

use Codeprint\CheckoutFirewall\Operations\FreeIncidentState;

final class FreeIncidentNotice {
	public const ACTION = 'checkout_firewall_dismiss_free_incident';

	public function __construct( private FreeIncidentState $state ) {}

	public function register(): void {
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'dismiss' ) );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			return;
		}
		$state = $this->state->read();
		$last  = null !== $state ? strtotime( (string) $state['last_signal_at_gmt'] . ' UTC' ) : false;
		if ( null === $state || '' !== $state['dismissed_at_gmt'] || false === $last || $last < time() - FreeIncidentState::NOTICE_SECONDS - FreeIncidentState::QUIET_SECONDS ) {
			return;
		}
		$actual   = (int) $state['counts']['enforced_challenge'] + (int) $state['counts']['enforced_block'];
		$observed = (int) $state['counts']['observed_challenge'] + (int) $state['counts']['observed_block'];
		?>
		<div class="notice notice-warning"><p><strong><?php esc_html_e( 'Checkout Firewall detected elevated checkout-abuse signals.', 'checkout-firewall' ); ?></strong> <?php /* translators: 1: actual intervention count, 2: observed would-intervene count. */ echo esc_html( sprintf( __( '%1$d checkout decisions were enforced and %2$d were observed without intervention.', 'checkout-firewall' ), $actual, $observed ) ); ?> <?php esc_html_e( 'This is not a fraud determination.', 'checkout-firewall' ); ?> <a href="<?php echo esc_url( admin_url( 'admin.php?page=checkout-firewall&view=activity' ) ); ?>"><?php esc_html_e( 'Review Activity', 'checkout-firewall' ); ?></a></p><form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION ); ?>" /><input type="hidden" name="incident_id" value="<?php echo esc_attr( (string) $state['incident_id'] ); ?>" /><?php wp_nonce_field( self::ACTION . '_' . $state['incident_id'] ); ?><button class="button" type="submit"><?php esc_html_e( 'Dismiss', 'checkout-firewall' ); ?></button></form></div>
		<?php
	}

	public function dismiss(): void {
		$input = RequestNormalizer::post( 'incident_id', 64, '/^[a-z0-9_-]+$/D' );
		$id    = $input['invalid'] || null === $input['value'] ? '' : $input['value'];
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Checkout Firewall.', 'checkout-firewall' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION . '_' . $id );
		$this->state->dismiss( $id );
		wp_safe_redirect( admin_url( 'admin.php?page=checkout-firewall&view=activity' ) );
		exit;
	}
}
