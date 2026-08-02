<?php
/**
 * Session-backed, checkout-context-bound pending Turnstile challenge.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Turnstile;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\FlowProof\Base64Url;
use Codeprint\CheckoutFirewall\FlowProof\CartBinding;
use Codeprint\CheckoutFirewall\Security\KeyStore;

final class ChallengeCoordinator {
	public const SESSION_KEY    = 'cwf_turnstile_pending_v1';
	public const ACTION         = 'checkout_firewall_checkout';
	public const TTL            = 300;
	public const MAX_ATTEMPTS   = 5;
	private const STATE_CONTEXT = 'checkout-firewall/turnstile/state/v1';
	private const CDATA_CONTEXT = 'checkout-firewall/turnstile/cdata/v1';

	private TurnstileConfig $config;
	private TurnstileConflictDetector $conflicts;
	private KeyStore $keys;
	/**
	 * Clock seam.
	 *
	 * @var \Closure():int
	 */
	private \Closure $clock;
	/**
	 * Entropy seam.
	 *
	 * @var \Closure():string
	 */
	private \Closure $random;
	/**
	 * Checkout binding seam.
	 *
	 * @var \Closure():CartBinding
	 */
	private \Closure $binding;

	public function __construct(
		?TurnstileConfig $config = null,
		?TurnstileConflictDetector $conflicts = null,
		?KeyStore $keys = null,
		?callable $clock = null,
		?callable $random = null,
		?callable $binding = null
	) {
		$this->config    = $config ?? new TurnstileConfig();
		$this->conflicts = $conflicts ?? new TurnstileConflictDetector();
		$this->keys      = $keys ?? new KeyStore();
		$this->clock     = \Closure::fromCallable( $clock ?? 'time' );
		$this->random    = \Closure::fromCallable( $random ?? static fn(): string => random_bytes( 16 ) );
		$this->binding   = \Closure::fromCallable( $binding ?? array( CartBinding::class, 'from_woocommerce' ) );
	}

	public function issue( CheckoutContext $context ): bool {
		if ( ! $this->config->is_active() || $this->conflicts->has_conflict() ) {
			return false;
		}
		$binding = ( $this->binding )();
		$digest  = $this->binding_digest( $binding );
		$now     = ( $this->clock )();
		$current = $this->read();
		if ( null !== $current && $this->matches( $current, $context, $digest, $now ) ) {
			return true;
		}

		$state = Base64Url::encode( ( $this->random )() );
		if ( 22 !== strlen( $state ) ) {
			throw new \RuntimeException( 'Turnstile state entropy is unavailable.' );
		}
		$this->write(
			array(
				'format'     => 1,
				'state'      => $state,
				'surface'    => $context->surface(),
				'order_id'   => $context->order_id() ?? 0,
				'binding'    => $digest,
				'issued_at'  => $now,
				'expires_at' => $now + self::TTL,
				'attempts'   => 0,
				'status'     => 'pending',
			)
		);
		return true;
	}

	/**
	 * Return the public descriptor for the current pending challenge.
	 *
	 * @return array<string,mixed>|null
	 */
	public function descriptor(): ?array {
		if ( ! $this->config->is_active() || $this->conflicts->has_conflict() ) {
			return null;
		}
		$record = $this->validated_current();
		if ( null === $record ) {
			return null;
		}
		$credentials = $this->config->credentials();
		return array(
			'site_key'   => $credentials['site_key'],
			'state'      => $record['state'],
			'cdata'      => $this->cdata( $record ),
			'action'     => self::ACTION,
			'expires_at' => $record['expires_at'],
			'title'      => __( 'Verify your checkout', 'checkout-firewall' ),
			'message'    => __( 'An extra check is needed before this order can continue. Complete it, then we’ll retry once.', 'checkout-firewall' ),
			'privacy'    => __( 'This check uses Cloudflare Turnstile. Checkout Firewall does not send payment details to Cloudflare.', 'checkout-firewall' ),
		);
	}

	/**
	 * Validate and charge one Siteverify attempt.
	 *
	 * @return array{hostname:string,cdata:string}|null
	 */
	public function submission( CheckoutContext $context, string $state ): ?array {
		$record = $this->validated_current();
		if ( null === $record || ! $this->matches( $record, $context, $record['binding'], ( $this->clock )() )
			|| ! hash_equals( $record['state'], $state ) || $record['attempts'] >= self::MAX_ATTEMPTS
		) {
			return null;
		}
		++$record['attempts'];
		$this->write( $record );
		return array(
			'hostname' => TurnstileConfig::current_hostname(),
			'cdata'    => $this->cdata( $record ),
		);
	}

	public function attempts_exhausted( CheckoutContext $context, string $state ): bool {
		$record = $this->validated_current();
		return null !== $record && $record['attempts'] >= self::MAX_ATTEMPTS
			&& hash_equals( $record['state'], $state )
			&& $this->matches( $record, $context, $record['binding'], ( $this->clock )() );
	}

	public function consume(): void {
		$session = $this->session();
		if ( method_exists( $session, '__unset' ) ) {
			$session->__unset( self::SESSION_KEY );
			return;
		}
		$session->set( self::SESSION_KEY, null );
	}

	/**
	 * Read a current context-bound challenge.
	 *
	 * @return array<string,mixed>|null
	 */
	private function validated_current(): ?array {
		$record = $this->read();
		if ( null === $record || $record['expires_at'] < ( $this->clock )() || 'pending' !== $record['status'] ) {
			$this->consume();
			return null;
		}
		$binding = ( $this->binding )();
		if ( ! hash_equals( $record['binding'], $this->binding_digest( $binding ) ) ) {
			$this->consume();
			return null;
		}
		return $record;
	}

	/**
	 * Check a pending record against an evaluation context.
	 *
	 * @param array<string,mixed> $record Pending record.
	 */
	private function matches( array $record, CheckoutContext $context, string $binding, int $now ): bool {
		return 'pending' === $record['status'] && $record['expires_at'] >= $now
			&& hash_equals( $record['surface'], $context->surface() )
			&& ( $context->order_id() ?? 0 ) === $record['order_id']
			&& hash_equals( $record['binding'], $binding );
	}

	private function binding_digest( CartBinding $binding ): string {
		$key = $this->keys->derive_turnstile_key( self::STATE_CONTEXT );
		return hash_hmac( 'sha256', $binding->host() . "\0" . $binding->session_source() . "\0" . $binding->cart_source(), $key['material'] );
	}

	/**
	 * Create the public signed cData value.
	 *
	 * @param array<string,mixed> $record Pending record.
	 */
	private function cdata( array $record ): string {
		$key    = $this->keys->derive_turnstile_key( self::CDATA_CONTEXT );
		$source = "1\0{$record['state']}\0{$record['surface']}\0{$record['binding']}\0{$record['expires_at']}";
		return substr( Base64Url::encode( hash_hmac( 'sha256', $source, $key['material'], true ) ), 0, 43 );
	}

	/**
	 * Read and validate the bounded session record shape.
	 *
	 * @return array<string,mixed>|null
	 */
	private function read(): ?array {
		$value = $this->session()->get( self::SESSION_KEY, null );
		if ( ! is_array( $value ) || 1 !== (int) ( $value['format'] ?? 0 )
			|| ! is_string( $value['state'] ?? null ) || 22 !== strlen( $value['state'] )
			|| ! is_string( $value['surface'] ?? null ) || ! is_int( $value['order_id'] ?? null )
			|| ! is_string( $value['binding'] ?? null ) || 64 !== strlen( $value['binding'] )
			|| ! is_int( $value['issued_at'] ?? null ) || ! is_int( $value['expires_at'] ?? null )
			|| ! is_int( $value['attempts'] ?? null ) || $value['attempts'] < 0 || $value['attempts'] > self::MAX_ATTEMPTS
			|| 'pending' !== ( $value['status'] ?? null )
		) {
			return null;
		}
		return $value;
	}

	/**
	 * Write one pending record to the WooCommerce session.
	 *
	 * @param array<string,mixed> $record Pending record.
	 */
	private function write( array $record ): void {
		$this->session()->set( self::SESSION_KEY, $record );
	}

	private function session(): object {
		$woocommerce = WC();
		if ( ! is_object( $woocommerce->session ) || ! method_exists( $woocommerce->session, 'get' ) || ! method_exists( $woocommerce->session, 'set' ) ) {
			throw new \RuntimeException( 'WooCommerce challenge session is unavailable.' );
		}
		return $woocommerce->session;
	}
}
