<?php
/**
 * Checkout Blocks proof script integration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Automattic\WooCommerce\Blocks\Integrations\IntegrationInterface;
use Codeprint\CheckoutFirewall\Challenge\ChallengeClassicClient;
use Codeprint\CheckoutFirewall\Challenge\ChallengeEndpoint;

final class CheckoutBlocksIntegration implements IntegrationInterface {
	private const HANDLE           = 'checkout-firewall-flow-proof-blocks';
	private const CORE_HANDLE      = 'checkout-firewall-flow-proof-core';
	private const CHALLENGE_HANDLE = 'checkout-firewall-challenge-blocks';

	public function get_name(): string {
		return 'checkout-firewall-flow-proof';
	}

	public function initialize(): void {
		wp_register_script(
			self::CORE_HANDLE,
			plugins_url( 'assets/js/checkout-flow-proof-core.js', CWF_PLUGIN_FILE ),
			array(),
			CWF_VERSION,
			true
		);
		ChallengeClassicClient::register_assets();
		wp_register_script(
			self::CHALLENGE_HANDLE,
			plugins_url( 'assets/js/checkout-challenge-blocks.js', CWF_PLUGIN_FILE ),
			array( 'wp-api-fetch', 'wp-data', 'wc-blocks-data-store', 'wc-blocks-checkout-events', 'wc-settings', 'checkout-firewall-challenge-core' ),
			CWF_VERSION,
			true
		);
		wp_enqueue_style( 'checkout-firewall-checkout' );
		wp_register_script(
			self::HANDLE,
			plugins_url( 'assets/js/checkout-flow-proof-blocks.js', CWF_PLUGIN_FILE ),
			array( 'wp-data', 'wc-blocks-data-store', 'wc-settings', self::CORE_HANDLE ),
			CWF_VERSION,
			true
		);
	}

	/**
	 * Return frontend script handles.
	 *
	 * @return list<string>
	 */
	public function get_script_handles(): array {
		return array( self::HANDLE, self::CHALLENGE_HANDLE );
	}

	/**
	 * Return editor script handles.
	 *
	 * @return list<string>
	 */
	public function get_editor_script_handles(): array {
		return array();
	}

	/**
	 * Return cache-safe frontend settings.
	 *
	 * @return array<string,mixed>
	 */
	public function get_script_data(): array {
		return array(
			'endpoint'          => rest_url( MintEndpoint::NAMESPACE . MintEndpoint::ROUTE ),
			'action'            => FlowProofService::ACTION,
			'namespace'         => 'checkout-firewall',
			'refreshLeadMs'     => 60000,
			'challengeEndpoint' => rest_url( ChallengeEndpoint::NAMESPACE . ChallengeEndpoint::ROUTE ),
			'challengeStrings'  => ChallengeClassicClient::script_strings(),
			'localScript'       => plugins_url( 'assets/vendor/altcha/altcha.js', CWF_PLUGIN_FILE ),
			'localWorker'       => plugins_url( 'assets/vendor/altcha/pbkdf2.js', CWF_PLUGIN_FILE ),
			'localStyle'        => plugins_url( 'assets/vendor/altcha/altcha.css', CWF_PLUGIN_FILE ),
			'language'          => strtolower( substr( determine_locale(), 0, 2 ) ),
		);
	}
}
