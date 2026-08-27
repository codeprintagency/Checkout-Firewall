<?php
/**
 * Classic WooCommerce Checkout enforcement adapter.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Enforcement;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;
use Codeprint\CheckoutFirewall\Challenge\ChallengeClassicClient;
use Codeprint\CheckoutFirewall\Challenge\ChallengeInputRegistry;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\FlowProof\ClassicCheckoutClient;
use Codeprint\CheckoutFirewall\FlowProof\CheckoutEvidenceInputRegistry;
use Codeprint\CheckoutFirewall\FlowProof\FlowProofInputRegistry;
use Codeprint\CheckoutFirewall\Protection\IdentityRegistry;
use Codeprint\CheckoutFirewall\Protection\PaymentFeedback;
use Codeprint\CheckoutFirewall\Security\RequestNormalizer;
use Codeprint\CheckoutFirewall\Support\SafeLogger;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileClassicClient;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileInputRegistry;

final class ClassicCheckoutAdapter {
	private CheckoutGuard $guard;
	private FlowProofInputRegistry $proof_inputs;
	private ?IdentityRegistry $identities;
	private ?PaymentFeedback $feedback;
	private ?TurnstileInputRegistry $turnstile_inputs;
	private ?ChallengeInputRegistry $challenge_inputs;
	private ?CheckoutEvidenceInputRegistry $evidence_inputs;

	public function __construct( CheckoutGuard $guard, ?FlowProofInputRegistry $proof_inputs = null, ?IdentityRegistry $identities = null, ?PaymentFeedback $feedback = null, ?TurnstileInputRegistry $turnstile_inputs = null, ?ChallengeInputRegistry $challenge_inputs = null, ?CheckoutEvidenceInputRegistry $evidence_inputs = null ) {
		$this->guard            = $guard;
		$this->proof_inputs     = $proof_inputs ?? new FlowProofInputRegistry();
		$this->identities       = $identities;
		$this->feedback         = $feedback;
		$this->turnstile_inputs = $turnstile_inputs;
		$this->challenge_inputs = $challenge_inputs;
		$this->evidence_inputs  = $evidence_inputs;
	}

	public function register(): void {
		add_action( 'woocommerce_after_checkout_validation', array( $this, 'validate' ), 999, 2 );
		add_action( 'woocommerce_checkout_order_processed', array( $this, 'assert_before_payment' ), 0, 3 );
	}

	/**
	 * Evaluate valid Classic Checkout data before customer or order creation.
	 *
	 * @param array<string,mixed> $data Sanitized checkout data.
	 * @throws \RuntimeException Never escapes; converted to the required fail-open result.
	 */
	public function validate( array $data, \WP_Error $errors ): void {
		if ( $errors->has_errors() ) {
			return;
		}

		try {
			$cart = WC()->cart;
			if ( null === $cart ) {
				throw new \RuntimeException( 'Classic checkout cart is unavailable.' );
			}

			$context = new CheckoutContext(
				CheckoutSurface::CLASSIC,
				is_user_logged_in(),
				(int) $cart->get_cart_contents_count(),
				(bool) $cart->needs_payment(),
				self::minor_units( $cart->get_total( 'edit' ) ),
				isset( $data['payment_method'] ) && is_string( $data['payment_method'] ) ? $data['payment_method'] : ''
			);
			// phpcs:disable WordPress.Security.NonceVerification.Missing -- WooCommerce verified its checkout nonce before this hook; read only the exact proof field.
			$proof = RequestNormalizer::post( ClassicCheckoutClient::FIELD, \Codeprint\CheckoutFirewall\FlowProof\FlowProofService::MAX_TOKEN_SIZE );
			$this->proof_inputs->record( $context, $proof['value'], $proof['present'], $proof['invalid'] );
			if ( null !== $this->challenge_inputs ) {
				$token = RequestNormalizer::post( ChallengeClassicClient::TOKEN_FIELD, \Codeprint\CheckoutFirewall\Challenge\LocalProofService::MAX_PAYLOAD );
				$state = RequestNormalizer::post( ChallengeClassicClient::STATE_FIELD, \Codeprint\CheckoutFirewall\Challenge\ChallengeCandidateProvider::MAX_STATE );
				$this->challenge_inputs->record( $context, $token['value'], $state['value'], $token['present'] || $state['present'], $token['invalid'] || $state['invalid'] );
			}
			if ( null !== $this->evidence_inputs ) {
				$evidence = RequestNormalizer::post( ClassicCheckoutClient::EVIDENCE_FIELD, \Codeprint\CheckoutFirewall\FlowProof\CheckoutEvidenceService::MAX_TOKEN );
				$name     = RequestNormalizer::post( ClassicCheckoutClient::HONEYPOT_NAME_FIELD, 40, '/^checkout_firewall_hp_[a-f0-9]{16}$/D' );
				$honeypot = null === $name['value']
					? array(
						'value'   => null,
						'invalid' => false,
						'present' => false,
					)
					: RequestNormalizer::post( $name['value'], 256 );
				$this->evidence_inputs->record( $context, $evidence['value'], $name['value'], $honeypot['value'], $evidence['present'] || $name['present'] || $honeypot['present'], $evidence['invalid'] || $name['invalid'] || $honeypot['invalid'] );
			}
			if ( null !== $this->turnstile_inputs ) {
				$token = RequestNormalizer::post( TurnstileClassicClient::TOKEN_FIELD, \Codeprint\CheckoutFirewall\Turnstile\SiteverifyClient::MAX_TOKEN );
				$state = RequestNormalizer::post( TurnstileClassicClient::STATE_FIELD, \Codeprint\CheckoutFirewall\Turnstile\TurnstileProvider::MAX_STATE );
				$this->turnstile_inputs->record( $context, $token['value'], $state['value'], $token['present'] || $state['present'], $token['invalid'] || $state['invalid'] );
			}
			// phpcs:enable WordPress.Security.NonceVerification.Missing
			if ( null !== $this->identities ) {
				$this->identities->record( $context, $data['billing_email'] ?? null );
			}

			$result = $this->guard->evaluate( $context );
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'classic_checkout_guard_failed', $exception );
			return;
		}

		if ( ! $result->allows_checkout() ) {
			$code = DecisionAction::CHALLENGE === $result->action()
				? 'checkout_firewall_challenge_required'
				: ( in_array( $result->reason(), array( ReasonCode::CHALLENGE_UNAVAILABLE, ReasonCode::VELOCITY_THROTTLED ), true ) ? 'checkout_firewall_checkout_throttled' : 'checkout_firewall_checkout_blocked' );
			$errors->add( $code, $result->customer_message() );
		}
	}

	/**
	 * Secondary assertion immediately before Classic payment processing.
	 *
	 * @param int                 $order_id Order ID.
	 * @param array<string,mixed> $data Sanitized checkout data.
	 * @param mixed               $order WooCommerce order.
	 * @throws \Exception When a recorded non-allow decision reaches payment.
	 */
	public function assert_before_payment( int $order_id, array $data, $order ): void {
		unset( $order_id, $data );
		$result = $this->guard->classic_result();
		if ( null === $result ) {
			SafeLogger::error( 'classic_checkout_decision_missing' );
			return;
		}
		if ( ! $result->allows_checkout() ) {
			throw new \Exception( esc_html( $result->customer_message() ) );
		}
		if ( null !== $this->feedback && null !== $this->identities && $order instanceof \WC_Order ) {
			$context = new CheckoutContext( CheckoutSurface::CLASSIC, is_user_logged_in(), 0, $order->needs_payment(), self::minor_units( $order->get_total() ), $order->get_payment_method() );
			$this->feedback->arm( $order, $this->identities->read( $context ), $order->get_payment_method() );
		}
	}

	/**
	 * Convert a WooCommerce decimal into non-negative minor units.
	 *
	 * @param mixed $amount WooCommerce decimal total.
	 */
	private static function minor_units( $amount ): int {
		$decimals = max( 0, min( 6, (int) wc_get_price_decimals() ) );
		return max( 0, (int) round( (float) $amount * ( 10 ** $decimals ) ) );
	}
}
