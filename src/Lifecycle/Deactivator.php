<?php
/**
 * Non-destructive deactivation lifecycle.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Lifecycle;

use Codeprint\CheckoutFirewall\Scheduler\CleanupScheduler;

final class Deactivator {
	/**
	 * Deactivate without deleting persistent data.
	 *
	 * @param mixed $network_wide WordPress network activation flag.
	 */
	public static function deactivate( $network_wide = false ): void {
		unset( $network_wide );
		CleanupScheduler::unschedule();
		if ( function_exists( 'as_unschedule_all_actions' ) ) {
			as_unschedule_all_actions( 'checkout_firewall_pro_alert_delivery', array(), 'checkout-firewall-pro-alerts' );
		}
	}
}
