<?php
/**
 * WooCommerce Store API checkout enforcement adapter.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Enforcement;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Challenge\ChallengeInputRegistry;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionResult;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\FlowProof\FlowProofInputRegistry;
use Codeprint\CheckoutFirewall\FlowProof\CheckoutEvidenceInputRegistry;
use Codeprint\CheckoutFirewall\Protection\IdentityRegistry;
use Codeprint\CheckoutFirewall\Protection\PaymentFeedback;
use Codeprint\CheckoutFirewall\Support\SafeLogger;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileInputRegistry;

final class StoreApiCheckoutAdapter {
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
		add_action( 'woocommerce_store_api_checkout_update_order_from_request', array( $this, 'validate' ), 0, 2 );
		add_action( 'woocommerce_store_api_checkout_order_processed', array( $this, 'assert_before_payment' ), 0, 1 );
	}

	/**
	 * Evaluate an exact Store API checkout request before payment.
	 *
	 * @param mixed $order WooCommerce order.
	 * @param mixed $request Store API request.
	 * @throws \UnexpectedValueException Never escapes; converted to fail-open behavior.
	 */
	public function validate( $order, $request ): void {
		try {
			if ( ! is_object( $request ) || ! method_exists( $request, 'get_method' ) || ! method_exists( $request, 'get_route' ) ) {
				throw new \UnexpectedValueException( 'Store API request is unavailable.' );
			}

			$surface = StoreApiRouteMatcher::surface( (string) $request->get_method(), (string) $request->get_route() );
			if ( null === $surface ) {
				return;
			}
			if ( ! is_object( $order ) || ! method_exists( $order, 'get_id' ) ) {
				throw new \UnexpectedValueException( 'Store API order is unavailable.' );
			}

			$order_id = (int) $order->get_id();
			$gateway  = method_exists( $order, 'get_payment_method' ) ? (string) $order->get_payment_method() : '';
			if ( '' === $gateway && method_exists( $request, 'get_param' ) ) {
				$payment_method = $request->get_param( 'payment_method' );
				$gateway        = is_string( $payment_method ) ? $payment_method : '';
			}

			$context = new CheckoutContext(
				$surface,
				is_user_logged_in(),
				self::cart_item_count( $order ),
				method_exists( $order, 'needs_payment' ) && (bool) $order->needs_payment(),
				self::minor_units( method_exists( $order, 'get_total' ) ? $order->get_total() : 0 ),
				$gateway,
				$order_id
			);

			$extensions = method_exists( $request, 'get_param' ) ? $request->get_param( 'extensions' ) : null;
			$namespace  = is_array( $extensions ) && isset( $extensions['checkout-firewall'] ) && is_array( $extensions['checkout-firewall'] )
				? $extensions['checkout-firewall']
				: array();
			$present    = array_key_exists( 'flow_proof', $namespace );
			$this->proof_inputs->record( $context, $present ? $namespace['flow_proof'] : null, $present );
			if ( null !== $this->challenge_inputs ) {
				$token_present = array_key_exists( 'challenge_token', $namespace );
				$state_present = array_key_exists( 'challenge_state', $namespace );
				$this->challenge_inputs->record( $context, $token_present ? $namespace['challenge_token'] : null, $state_present ? $namespace['challenge_state'] : null, $token_present || $state_present );
			}
			if ( null !== $this->evidence_inputs ) {
				$evidence_present = array_key_exists( 'evidence_token', $namespace );
				$name_present     = array_key_exists( 'honeypot_field', $namespace );
				$value_present    = array_key_exists( 'honeypot_value', $namespace );
				$this->evidence_inputs->record( $context, $evidence_present ? $namespace['evidence_token'] : null, $name_present ? $namespace['honeypot_field'] : null, $value_present ? $namespace['honeypot_value'] : null, $evidence_present || $name_present || $value_present );
			}
			if ( null !== $this->turnstile_inputs ) {
				$token_present = array_key_exists( 'turnstile_token', $namespace );
				$state_present = array_key_exists( 'turnstile_state', $namespace );
				$this->turnstile_inputs->record(
					$context,
					$token_present ? $namespace['turnstile_token'] : null,
					$state_present ? $namespace['turnstile_state'] : null,
					$token_present || $state_present
				);
			}
			if ( null !== $this->identities ) {
				$email = method_exists( $order, 'get_billing_email' ) ? $order->get_billing_email() : null;
				$this->identities->record( $context, $email );
			}

			$result = $this->guard->evaluate( $context );
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'store_api_checkout_guard_failed', $exception );
			return;
		}

		$this->enforce( $result );
	}

	/**
	 * Secondary assertion immediately before Store API payment processing.
	 *
	 * @param mixed $order WooCommerce order.
	 * @throws \Automattic\WooCommerce\StoreApi\Exceptions\RouteException When a recorded intervention reaches payment.
	 */
	public function assert_before_payment( $order ): void {
		if ( ! is_object( $order ) || ! method_exists( $order, 'get_id' ) ) {
			SafeLogger::error( 'store_api_checkout_order_missing' );
			return;
		}

		$result = $this->guard->order_result( (int) $order->get_id() );
		if ( null === $result ) {
			SafeLogger::error( 'store_api_checkout_decision_missing' );
			return;
		}
		$this->enforce( $result );
		if ( null !== $this->feedback && null !== $this->identities && $order instanceof \WC_Order ) {
			$context = new CheckoutContext(
				\Codeprint\CheckoutFirewall\Checkout\CheckoutSurface::STORE_API_ORDER,
				is_user_logged_in(),
				self::cart_item_count( $order ),
				$order->needs_payment(),
				self::minor_units( $order->get_total() ),
				$order->get_payment_method(),
				$order->get_id()
			);
			$this->feedback->arm( $order, $this->identities->read( $context ), $order->get_payment_method() );
		}
	}

	private function enforce( DecisionResult $result ): void {
		if ( $result->allows_checkout() ) {
			return;
		}

		$challenge = DecisionAction::CHALLENGE === $result->action();
		$throttle  = ReasonCode::CHALLENGE_UNAVAILABLE === $result->reason();
		$code      = $challenge
			? 'checkout_firewall_challenge_required'
			: ( $throttle ? 'checkout_firewall_checkout_throttled' : 'checkout_firewall_checkout_blocked' );
		$status    = $challenge ? 409 : ( $throttle ? 429 : 403 );
		throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException(
			sanitize_key( $code ),
			esc_html( $result->customer_message() ),
			absint( $status )
		);
	}

	/**
	 * Read an already-loaded cart or order item count.
	 *
	 * @param mixed $order WooCommerce order.
	 */
	private static function cart_item_count( $order ): int {
		$woocommerce = WC();
		if ( null !== $woocommerce->cart ) {
			return max( 0, (int) $woocommerce->cart->get_cart_contents_count() );
		}
		return method_exists( $order, 'get_item_count' ) ? max( 0, (int) $order->get_item_count() ) : 0;
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
