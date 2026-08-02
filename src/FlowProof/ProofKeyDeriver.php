<?php
/**
 * Domain-separated proof key access.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Security\KeyStore;

final class ProofKeyDeriver {
	public const SIGN_CONTEXT    = 'checkout-firewall/flow-proof/sign/v1';
	public const SESSION_CONTEXT = 'checkout-firewall/flow-proof/session/v1';
	public const CART_CONTEXT    = 'checkout-firewall/flow-proof/cart/v1';
	public const TOKEN_CONTEXT   = 'checkout-firewall/flow-proof/token-id/v1';
	public const CONTEXT_CONTEXT = 'checkout-firewall/flow-proof/context/v1';

	private KeyStore $key_store;

	public function __construct( ?KeyStore $key_store = null ) {
		$this->key_store = $key_store ?? new KeyStore();
	}

	public function current_version(): int {
		return $this->key_store->current_version();
	}

	/**
	 * Derive one allowlisted proof subkey for a retained version.
	 *
	 * @return array{key_version:int,key_fingerprint:string,material:string}
	 */
	public function derive( string $context, int $version ): array {
		return $this->key_store->derive_flow_proof_key( $context, $version );
	}
}
