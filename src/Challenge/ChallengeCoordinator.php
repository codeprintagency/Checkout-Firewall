<?php
/**
 * Session-backed, checkout-bound selected-provider challenge coordinator.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Challenge;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\FlowProof\Base64Url;
use Codeprint\CheckoutFirewall\FlowProof\CartBinding;
use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;

final class ChallengeCoordinator {
	public const SESSION_KEY    = 'checkout_firewall_challenge_pending_v1';
	public const ACTION         = 'checkout_firewall_checkout';
	public const TTL            = 300;
	public const MAX_ATTEMPTS   = 5;
	private const STATE_CONTEXT = 'checkout-firewall/challenge/state/v1';

	private ChallengeConfig $config;
	private LocalProofService $local;
	private KeyStore $keys;
	/**
	 * Current timestamp provider.
	 *
	 * @var \Closure():int
	 */
	private \Closure $clock;
	/**
	 * Secure challenge-state provider.
	 *
	 * @var \Closure():string
	 */
	private \Closure $random;
	/**
	 * Current checkout-binding provider.
	 *
	 * @var \Closure():CartBinding
	 */
	private \Closure $binding;

	public function __construct(
		?ChallengeConfig $config = null,
		?LocalProofService $local = null,
		?KeyStore $keys = null,
		?callable $clock = null,
		?callable $random = null,
		?callable $binding = null
	) {
		$this->config  = $config ?? new ChallengeConfig();
		$this->local   = $local ?? new LocalProofService();
		$this->keys    = $keys ?? new KeyStore();
		$this->clock   = \Closure::fromCallable( $clock ?? 'time' );
		$this->random  = \Closure::fromCallable( $random ?? static fn(): string => random_bytes( 16 ) );
		$this->binding = \Closure::fromCallable( $binding ?? array( CartBinding::class, 'from_woocommerce' ) );
	}

	public function issue( CheckoutContext $context, bool $preflight = false ): bool {
		$provider = $this->config->effective();
		if ( ChallengeConfig::NONE === $provider ) {
			return false;
		}
		$binding = ( $this->binding )();
		$digest  = $this->binding_digest( $binding );
		$now     = ( $this->clock )();
		$current = $this->read();
		if ( null !== $current && $this->matches( $current, $context, $digest, $now )
			&& $this->config->accepts_pending( $current['provider'], $current['selected_provider'] )
		) {
			return true;
		}
		$state = Base64Url::encode( ( $this->random )() );
		if ( 22 !== strlen( $state ) ) {
			throw new \RuntimeException( 'Challenge state entropy is unavailable.' );
		}
		$record = array(
			'format'            => 1,
			'provider'          => $provider,
			'selected_provider' => $this->config->selected(),
			'state'             => $state,
			'surface'           => $context->surface(),
			'order_id'          => $context->order_id() ?? 0,
			'binding'           => $digest,
			'issued_at'         => $now,
			'expires_at'        => $now + self::TTL,
			'attempts'          => 0,
			'status'            => 'pending',
			'preflight'         => $preflight,
			'local_challenge'   => null,
		);
		if ( ChallengeConfig::LOCAL === $provider ) {
			$record['local_challenge'] = $this->local->create( $state, $record['expires_at'] );
		}
		$this->write( $record );
		return true;
	}

	/**
	 * Describe the current pending challenge without caching.
	 *
	 * @return array<string,mixed>|null
	 */
	public function descriptor(): ?array {
		$record = $this->validated_current();
		if ( null === $record || ! $this->config->accepts_pending( $record['provider'], $record['selected_provider'] ) ) {
			return null;
		}
		$base = array(
			'provider'   => $record['provider'],
			'state'      => $record['state'],
			'expires_at' => $record['expires_at'],
			'title'      => __( 'Complete a checkout security check', 'checkout-firewall' ),
			'message'    => __( 'Checkout Firewall needs one extra check before this order can continue. It will retry the checkout once after verification.', 'checkout-firewall' ),
		);
		if ( ChallengeConfig::LOCAL === $record['provider'] ) {
			$base['challenge'] = $record['local_challenge'];
			$base['privacy']   = __( 'This private proof-of-work check runs in your browser and is verified by this store. No challenge data is sent to an outside provider.', 'checkout-firewall' );
			return $base;
		}
		if ( ChallengeConfig::TURNSTILE === $record['provider'] ) {
			$credentials      = $this->config->turnstile()->credentials();
			$base['site_key'] = $credentials['site_key'];
			$base['action']   = self::ACTION;
			$base['cdata']    = $this->cdata( $record );
			$base['privacy']  = __( 'This check uses Cloudflare Turnstile. Checkout Firewall does not send payment details or the optional shopper IP to Cloudflare.', 'checkout-firewall' );
			return $base;
		}
		if ( ChallengeConfig::RECAPTCHA === $record['provider'] ) {
			$credentials      = $this->config->recaptcha()->credentials();
			$base['site_key'] = $credentials['site_key'];
			$base['privacy']  = __( 'This check uses Google reCAPTCHA. The shopper browser contacts Google; Checkout Firewall sends no payment details to Google.', 'checkout-firewall' );
			return $base;
		}
		return null;
	}

	/**
	 * Claim one bounded verification attempt.
	 *
	 * @return array{provider:string,hostname:string,cdata:string,expires_at:int}|null
	 */
	public function submission( CheckoutContext $context, string $state ): ?array {
		$record = $this->validated_current();
		if ( null === $record || ! $this->matches( $record, $context, $record['binding'], ( $this->clock )() )
			|| ! hash_equals( $record['state'], $state ) || $record['attempts'] >= self::MAX_ATTEMPTS
			|| ! $this->config->accepts_pending( $record['provider'], $record['selected_provider'] )
		) {
			return null;
		}
		if ( true === $record['preflight'] && 0 === $record['order_id'] && null !== $context->order_id() ) {
			$record['order_id'] = $context->order_id();
		}
		++$record['attempts'];
		$this->write( $record );
		return array(
			'provider'   => $record['provider'],
			'hostname'   => TurnstileConfig::current_hostname(),
			'cdata'      => ChallengeConfig::TURNSTILE === $record['provider'] ? $this->cdata( $record ) : '',
			'expires_at' => $record['expires_at'],
		);
	}

	public function attempts_exhausted( CheckoutContext $context, string $state ): bool {
		$record = $this->validated_current();
		return null !== $record && $record['attempts'] >= self::MAX_ATTEMPTS && hash_equals( $record['state'], $state )
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
	 * Read and validate the current pending challenge.
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
	 * Match a challenge to an exact checkout context.
	 *
	 * @param array<string,mixed> $record Pending record.
	 */
	private function matches( array $record, CheckoutContext $context, string $binding, int $now ): bool {
		$order_matches = ( $context->order_id() ?? 0 ) === $record['order_id']
			|| ( true === ( $record['preflight'] ?? false ) && 0 === $record['order_id'] && null !== $context->order_id() );
		return 'pending' === $record['status'] && $record['expires_at'] >= $now
			&& hash_equals( $record['surface'], $context->surface() )
			&& $order_matches
			&& hash_equals( $record['binding'], $binding );
	}

	private function binding_digest( CartBinding $binding ): string {
		$key = $this->keys->derive_challenge_key( self::STATE_CONTEXT );
		return hash_hmac( 'sha256', $binding->host() . "\0" . $binding->session_source() . "\0" . $binding->cart_source(), $key['material'] );
	}

	/**
	 * Derive bounded Turnstile cData for one pending record.
	 *
	 * @param array<string,mixed> $record Pending record.
	 */
	private function cdata( array $record ): string {
		$key    = $this->keys->derive_turnstile_key( 'checkout-firewall/turnstile/cdata/v1' );
		$source = "1\0{$record['state']}\0{$record['surface']}\0{$record['binding']}\0{$record['expires_at']}";
		return substr( Base64Url::encode( hash_hmac( 'sha256', $source, $key['material'], true ) ), 0, 43 );
	}

	/**
	 * Read one structurally valid pending record.
	 *
	 * @return array<string,mixed>|null
	 */
	private function read(): ?array {
		$value = $this->session()->get( self::SESSION_KEY, null );
		if ( ! is_array( $value ) || 1 !== (int) ( $value['format'] ?? 0 )
			|| ! is_string( $value['provider'] ?? null ) || ! in_array( $value['provider'], array( ChallengeConfig::LOCAL, ChallengeConfig::TURNSTILE, ChallengeConfig::RECAPTCHA ), true )
			|| ! is_string( $value['selected_provider'] ?? null ) || ! in_array( $value['selected_provider'], ChallengeConfig::PROVIDERS, true )
			|| ! is_string( $value['state'] ?? null ) || 22 !== strlen( $value['state'] )
			|| ! is_string( $value['surface'] ?? null ) || ! is_int( $value['order_id'] ?? null )
			|| ! is_string( $value['binding'] ?? null ) || 64 !== strlen( $value['binding'] )
			|| ! is_int( $value['issued_at'] ?? null ) || ! is_int( $value['expires_at'] ?? null )
			|| ! is_int( $value['attempts'] ?? null ) || $value['attempts'] < 0 || $value['attempts'] > self::MAX_ATTEMPTS
			|| 'pending' !== ( $value['status'] ?? null )
			|| ! is_bool( $value['preflight'] ?? null )
			|| ( ChallengeConfig::LOCAL === $value['provider'] && ! is_array( $value['local_challenge'] ?? null ) )
		) {
			return null;
		}
		return $value;
	}

	/**
	 * Persist one pending record in the WooCommerce session.
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
