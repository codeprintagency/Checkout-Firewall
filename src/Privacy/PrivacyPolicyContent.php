<?php
/**
 * Suggested site privacy-policy content.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Privacy;

use Codeprint\CheckoutFirewall\Admin\PremiumAdminPresenterRegistry;

final class PrivacyPolicyContent {
	public function register(): void {
		add_action( 'admin_init', array( $this, 'add' ) );
	}

	public function add(): void {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		$content  = __( 'Checkout Firewall locally processes keyed IP, email, session, and combined identifiers to protect WooCommerce checkout. It stores only HMAC-derived identifiers and approved masked hints, never raw payment data, card fields, gateway payloads, or request bodies. Checkout pages include a randomized empty honeypot field and signed short-lived render-time evidence; these are evaluated locally as supporting automation signals and are not retained as shopper profiles. The default private browser challenge performs bounded proof-of-work in the shopper browser and is verified by this store without contacting an outside challenge provider. A temporary keyed payment-feedback snapshot may be attached to a pending order so a later payment result can update local protection. It is deleted immediately after a recorded success or failure and otherwise expires within the configured activity-retention period of no more than seven days. Security event and terminal block history is retained for the configured period of no more than seven days; masked block hints are retained for no more than 90 days, while active enforcement may continue after a hint is removed. When configured and selected, Cloudflare Turnstile or Google reCAPTCHA loads only after a checkout challenge and may process browser and network information under the selected provider\'s terms. Checkout Firewall omits the optional shopper IP from server-side Turnstile verification and sends no payment details to either provider. Checkout Firewall sends no checkout telemetry to Codeprint and requires no Codeprint account. Optional Freemius connection is initiated only by an administrator after a consent screen and may transmit the administrator name and email, site URL and language, Checkout Firewall product version and state, WordPress and PHP versions, and installation or license identifiers needed for licensing and updates. Checkout Firewall does not request marketing email, diagnostic tracking, installed plugin or theme inventory, or affiliation data. The downloadable support snapshot is generated locally, is not uploaded, and excludes site identity, administrators, customers, identifiers, orders, gateways, keys, tokens, requests, logs, and raw errors. WordPress email-based erasure removes directly email-keyed rows and temporary payment-feedback snapshots, but cannot attribute IP, session, or combined records from an email alone. Plugin data is preserved on uninstall unless the site administrator explicitly authorizes full deletion.', 'checkout-firewall' );
		$content .= ' ' . __( 'A merchant may select Observe Mode, which records what the local engine would have challenged or blocked while allowing checkout to continue. Administrators may store bounded trusted exemptions for an authenticated local user, a keyed exact IP address, or a narrow raw CIDR needed for network-range matching. Sustained intervention signals may create a local identity-free incident notice and, when enabled, a rate-limited WordPress email containing counts but no shopper identity.', 'checkout-firewall' );
		$premium  = PremiumAdminPresenterRegistry::privacy_policy_paragraph();
		if ( '' !== $premium ) {
			$content .= ' ' . $premium;
		}
		wp_add_privacy_policy_content( 'Checkout Firewall', wp_kses_post( wpautop( $content, false ) ) );
	}
}
