<?php
/**
 * Request-local identity canonicalization and keyed hashing.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;
use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\FlowProof\CartBinding;
use Codeprint\CheckoutFirewall\Operations\IdentityMasker;
use Codeprint\CheckoutFirewall\Security\KeyStore;

final class IdentityRegistry {
	private KeyStore $keys;
	private ClientIpResolver $ips;
	/**
	 * Request-local identity sets keyed by checkout context.
	 *
	 * @var array<string,array<int,array<string,mixed>>>
	 */
	private array $sets = array();

	public function __construct( ?KeyStore $keys = null, ?ClientIpResolver $ips = null ) {
		$this->keys = $keys ?? new KeyStore();
		$this->ips  = $ips ?? new ClientIpResolver();
	}

	/**
	 * Canonicalize and hash identities for a checkout context.
	 *
	 * @param mixed $email Submitted billing email.
	 */
	public function record( CheckoutContext $context, $email ): void {
		$canonical = array();
		$ip        = $this->ips->resolve();
		if ( null !== $ip ) {
			$canonical[ IdentifierType::IP ] = $ip;
		}
		if ( is_string( $email ) ) {
			$email = strtolower( trim( sanitize_email( $email ) ) );
			if ( '' !== $email && strlen( $email ) <= 254 && is_email( $email ) ) {
				$canonical[ IdentifierType::EMAIL ] = $email;
			}
		}
		$session                              = CartBinding::session_identifier();
		$canonical[ IdentifierType::SESSION ] = $session;
		if ( isset( $canonical[ IdentifierType::IP ], $canonical[ IdentifierType::EMAIL ] ) ) {
			$ip_value                              = $canonical[ IdentifierType::IP ];
			$email_value                           = $canonical[ IdentifierType::EMAIL ];
			$canonical[ IdentifierType::IP_EMAIL ] = pack( 'n', strlen( $ip_value ) ) . $ip_value . pack( 'n', strlen( $email_value ) ) . $email_value;
		}

		$set = array();
		foreach ( $canonical as $type => $value ) {
			$hint = '';
			if ( IdentifierType::IP === $type ) {
				$hint = IdentityMasker::ip( $value );
			} elseif ( IdentifierType::EMAIL === $type ) {
				$hint = IdentityMasker::email( $value );
			} elseif ( IdentifierType::IP_EMAIL === $type && isset( $canonical[ IdentifierType::IP ], $canonical[ IdentifierType::EMAIL ] ) ) {
				$hint = IdentityMasker::ip( $canonical[ IdentifierType::IP ] ) . ' + ' . IdentityMasker::email( $canonical[ IdentifierType::EMAIL ] );
			}
			$set[ $type ] = array_merge(
				array(
					'identifier_type'      => $type,
					'display_hint'         => '' !== $hint ? $hint : null,
					'retained_identifiers' => $this->keys->hash_identifier_versions( $type, $value ),
				),
				$this->keys->hash_identifier( $type, $value ),
				$this->keys->active_key( $type, $value )
			);
		}
		$this->sets[ $this->key( $context ) ] = $set;
	}

	/**
	 * Read a previously recorded request-local identity set.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function read( CheckoutContext $context ): array {
		return $this->sets[ $this->key( $context ) ] ?? array();
	}

	/**
	 * Build the keyed identity used for gateway health counters.
	 *
	 * @return array<string,mixed>
	 * @throws \InvalidArgumentException When the gateway is empty.
	 */
	public function gateway( string $gateway ): array {
		$gateway = substr( sanitize_key( $gateway ), 0, 64 );
		if ( '' === $gateway ) {
			throw new \InvalidArgumentException( 'Gateway identity is unavailable.' );
		}
		return array_merge(
			array(
				'identifier_type'      => IdentifierType::GATEWAY,
				'retained_identifiers' => $this->keys->hash_identifier_versions( IdentifierType::GATEWAY, $gateway ),
			),
			$this->keys->hash_identifier( IdentifierType::GATEWAY, $gateway )
		);
	}

	private function key( CheckoutContext $context ): string {
		if ( CheckoutSurface::CLASSIC === $context->surface() ) {
			return 'classic';
		}
		return 'order:' . (string) ( $context->order_id() ?? 0 );
	}
}
