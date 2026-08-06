<?php
/**
 * WooCommerce-compatible payment outcome feedback.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Data\CounterType;
use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Operations\RetentionPolicy;
use Codeprint\CheckoutFirewall\Support\SafeLogger;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;
use Codeprint\CheckoutFirewall\Operations\FreeIncidentObserver;
use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;
use Codeprint\CheckoutFirewall\Decision\DecisionAction;
use Codeprint\CheckoutFirewall\Decision\DecisionResult;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;

final class PaymentFeedback {
	public const META_KEY        = '_checkout_firewall_m4_payment_attempt';
	public const EXPIRY_META_KEY = '_checkout_firewall_m4_payment_attempt_expires_at';
	private CounterRepository $counters;
	private BlockRepository $blocks;
	private GatewayHealth $health;
	private OperatingMode $mode;
	private ?TrustedExemptionMatcher $exemptions;
	private ?EventRepository $events;
	private ?FreeIncidentObserver $incidents;
	/**
	 * Orders awaiting synchronous payment-result classification.
	 *
	 * @var array<int,bool>
	 */
	private array $armed_orders = array();

	public function __construct( CounterRepository $counters, BlockRepository $blocks, GatewayHealth $health, ?OperatingMode $mode = null, ?TrustedExemptionMatcher $exemptions = null, ?EventRepository $events = null, ?FreeIncidentObserver $incidents = null ) {
		$this->counters   = $counters;
		$this->blocks     = $blocks;
		$this->health     = $health;
		$this->mode       = $mode ?? new OperatingMode();
		$this->exemptions = $exemptions;
		$this->events     = $events;
		$this->incidents  = $incidents;
	}

	public function register(): void {
		add_filter( 'woocommerce_payment_successful_result', array( $this, 'classic_accepted' ), PHP_INT_MAX, 2 );
		add_action( 'woocommerce_rest_checkout_process_payment_with_context', array( $this, 'store_result' ), PHP_INT_MAX, 2 );
		add_action( 'woocommerce_order_status_failed', array( $this, 'failed' ), 10, 2 );
		add_action( 'woocommerce_payment_complete', array( $this, 'paid' ), 10, 1 );
		add_action( 'woocommerce_order_payment_status_changed', array( $this, 'paid' ), 10, 1 );
		add_action( 'shutdown', array( $this, 'flush' ), PHP_INT_MAX );
	}

	/**
	 * Persist a keyed payment-attempt snapshot after checkout is allowed.
	 *
	 * @param mixed                           $order WooCommerce order.
	 * @param array<int,array<string,mixed>> $identities Keyed identities.
	 */
	public function arm( $order, array $identities, string $gateway ): void {
		if ( ! $order instanceof \WC_Order || array() === $identities ) {
			return;
		}
		$snapshot = array();
		foreach ( $identities as $type => $identity ) {
			if ( IdentifierType::GATEWAY === $type ) {
				continue;
			}
			$snapshot[ $type ] = array(
				'identifier_type'        => (int) $identity['identifier_type'],
				'display_hint'           => isset( $identity['display_hint'] ) && is_string( $identity['display_hint'] ) ? substr( $identity['display_hint'], 0, 191 ) : '',
				'key_version'            => (int) $identity['key_version'],
				'key_fingerprint'        => bin2hex( (string) $identity['key_fingerprint'] ),
				'identifier_hash'        => bin2hex( (string) $identity['identifier_hash'] ),
				'active_key_version'     => (int) $identity['active_key_version'],
				'active_key_fingerprint' => bin2hex( (string) $identity['active_key_fingerprint'] ),
				'active_key'             => bin2hex( (string) $identity['active_key'] ),
			);
		}
		if ( array() === $snapshot ) {
			return;
		}
		$attempt = array(
			'version'                   => 1,
			'attempt_id'                => bin2hex( random_bytes( 16 ) ),
			'state'                     => 'armed',
			'gateway'                   => substr( sanitize_key( $gateway ), 0, 64 ),
			'trusted_exemption_applied' => null !== $this->exemptions && null !== $this->exemptions->match(),
			'identities'                => $snapshot,
		);
		$order->delete_meta_data( self::META_KEY );
		$order->delete_meta_data( self::EXPIRY_META_KEY );
		$order->add_meta_data( self::META_KEY, $attempt, true );
		$order->add_meta_data( self::EXPIRY_META_KEY, gmdate( 'Y-m-d H:i:s', time() + RetentionPolicy::event_seconds() ), true );
		$order->save_meta_data();
		$this->armed_orders[ $order->get_id() ] = true;
	}

	/**
	 * Mark a classic payment handoff as accepted.
	 *
	 * @param mixed $result Gateway result.
	 * @return mixed
	 */
	public function classic_accepted( $result, int $order_id ): mixed {
		$this->mark_accepted( $order_id );
		return $result;
	}

	/**
	 * Mark a Store API payment handoff as accepted.
	 *
	 * @param mixed $context Store API payment context.
	 * @param mixed $result  Store API payment result.
	 */
	public function store_result( mixed $context, mixed $result ): void {
		try {
			if ( ! is_object( $context ) || ! method_exists( $context, 'get_order' ) || ! is_object( $result ) || ! method_exists( $result, 'get_status' ) ) {
				return;
			}
			$order = $context->get_order();
			if ( $order instanceof \WC_Order && 'success' === $result->get_status() ) {
				$this->mark_accepted( $order->get_id() );
			}
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'payment_feedback_store_result_failed', $exception );
		}
	}

	/**
	 * Record a WooCommerce failed-order outcome.
	 *
	 * @param mixed $order Optional order object supplied by WooCommerce.
	 */
	public function failed( int $order_id, $order = null ): void {
		try {
			$order = $order instanceof \WC_Order ? $order : wc_get_order( $order_id );
			if ( $order instanceof \WC_Order ) {
				$this->record_failure( $order, CounterType::GATEWAY_DECLINE );
			}
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'payment_feedback_decline_failed', $exception );
		}
	}

	public function paid( int $order_id ): void {
		try {
			$order = wc_get_order( $order_id );
			if ( $order instanceof \WC_Order ) {
				$this->record_success( $order );
			}
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'payment_feedback_success_failed', $exception );
		}
	}

	public function flush(): void {
		foreach ( array_keys( $this->armed_orders ) as $order_id ) {
			try {
				$order = wc_get_order( $order_id );
				if ( ! $order instanceof \WC_Order ) {
					continue;
				}
				$attempt = $this->attempt( $order );
				if ( null !== $attempt && 'armed' === $attempt['state'] ) {
					if ( $order->has_status( 'failed' ) ) {
						$this->record_failure( $order, CounterType::GATEWAY_DECLINE );
					} else {
						$this->record_failure( $order, CounterType::OTHER_FAILURE );
					}
				}
			} catch ( \Throwable $exception ) {
				SafeLogger::exception( 'payment_feedback_shutdown_failed', $exception );
			}
		}
		$this->armed_orders = array();
	}

	private function mark_accepted( int $order_id ): void {
		$order = wc_get_order( $order_id );
		if ( ! $order instanceof \WC_Order ) {
			return;
		}
		$attempt = $this->attempt( $order );
		if ( null === $attempt || 'armed' !== $attempt['state'] ) {
			return;
		}
		$attempt['state'] = 'accepted';
		$this->save_attempt( $order, $attempt );
		unset( $this->armed_orders[ $order_id ] );
	}

	private function record_success( \WC_Order $order ): void {
		$attempt = $this->attempt( $order );
		if ( null === $attempt || in_array( $attempt['state'], array( 'paid', 'decline', 'other' ), true ) ) {
			return;
		}
		$identities = $this->decode_identities( $attempt['identities'] );
		$gateway    = (string) $attempt['gateway'];
		$this->counters->increment( $identities, CounterType::PAYMENT_SUCCESS, '' );
		if ( '' !== $gateway ) {
			$this->counters->increment( $identities, CounterType::PAYMENT_SUCCESS, $gateway );
			$this->health->record( CounterType::PAYMENT_SUCCESS, $gateway );
			$this->blocks->release( $identities, $this->health->source( $gateway ) );
		}
		$this->delete_attempt( $order );
		unset( $this->armed_orders[ $order->get_id() ] );
		do_action( 'checkout_firewall_paid_outcome' );
	}

	private function record_failure( \WC_Order $order, int $counter_type ): void {
		$attempt = $this->attempt( $order );
		if ( null === $attempt || in_array( $attempt['state'], array( 'paid', 'decline', 'other' ), true ) ) {
			return;
		}
		$identities = $this->decode_identities( $attempt['identities'] );
		$gateway    = (string) $attempt['gateway'];
		$exempted   = true === ( $attempt['trusted_exemption_applied'] ?? false );
		if ( '' === $gateway ) {
			$this->delete_attempt( $order );
			unset( $this->armed_orders[ $order->get_id() ] );
			return;
		}
		$this->counters->increment( $identities, $counter_type, $gateway );
		$this->health->record( $counter_type, $gateway );
		$source = $this->health->source( $gateway );
		if ( $this->health->is_outage( $gateway ) ) {
			$this->blocks->release_source( $source );
		} else {
			$window        = CounterType::GATEWAY_DECLINE === $counter_type ? ProtectionPolicy::DECLINE_WINDOW : ProtectionPolicy::OTHER_WINDOW;
			$limit         = CounterType::GATEWAY_DECLINE === $counter_type ? ProtectionPolicy::DECLINE_LIMIT : ProtectionPolicy::OTHER_LIMIT;
			$lock          = CounterType::GATEWAY_DECLINE === $counter_type ? ProtectionPolicy::DECLINE_LOCK : ProtectionPolicy::OTHER_LOCK;
			$risk          = $this->counters->totals( $identities, $counter_type, $window, $gateway );
			$success       = $this->counters->totals( $identities, CounterType::PAYMENT_SUCCESS, $window, $gateway );
			$credit        = CounterType::GATEWAY_DECLINE === $counter_type ? 2 : 1;
			$would_lock    = false;
			$enforced_lock = false;
			foreach ( array( IdentifierType::EMAIL, IdentifierType::SESSION, IdentifierType::IP_EMAIL ) as $type ) {
				if ( isset( $identities[ $type ] ) && ProtectionPolicy::effective( $risk[ $type ] ?? 0, $success[ $type ] ?? 0, $credit ) >= $limit ) {
					if ( $this->mode->is_observing() && ! $exempted ) {
						$would_lock = true;
					} elseif ( ! $exempted ) {
						$this->blocks->lock( $identities[ $type ], $source, $lock );
						$enforced_lock = true;
					}
				}
			}
			try {
				if ( $would_lock && null !== $this->events ) {
					$decision = new DecisionResult( DecisionAction::BLOCK, ReasonCode::PAYMENT_FAILURE_LOCKOUT );
					$context  = new CheckoutContext( CheckoutSurface::STORE_API, false, 0, true, 0, $gateway, max( 1, $order->get_id() ) );
					$recorded = $this->events->record( $decision, $context, $identities, null, true );
					if ( $recorded && null !== $this->incidents ) {
						$this->incidents->observe( $decision, true );
					}
				} elseif ( $enforced_lock && null !== $this->incidents ) {
					$this->incidents->observe( new DecisionResult( DecisionAction::BLOCK, ReasonCode::PAYMENT_FAILURE_LOCKOUT ), false );
				}
			} catch ( \Throwable $exception ) {
				SafeLogger::exception( 'payment_feedback_incident_failed', $exception );
			}
		}
		$this->delete_attempt( $order );
		unset( $this->armed_orders[ $order->get_id() ] );
	}

	private function delete_attempt( \WC_Order $order ): void {
		$order->delete_meta_data( self::META_KEY );
		$order->delete_meta_data( self::EXPIRY_META_KEY );
		$order->save_meta_data();
	}

	/**
	 * Read and minimally validate the persisted attempt snapshot.
	 *
	 * @return array<string,mixed>|null
	 */
	private function attempt( \WC_Order $order ): ?array {
		$value = $order->get_meta( self::META_KEY, true );
		if ( ! is_array( $value ) || 1 !== ( $value['version'] ?? null ) || ! is_string( $value['attempt_id'] ?? null ) || 1 !== preg_match( '/^[a-f0-9]{32}$/D', $value['attempt_id'] ) || ! is_string( $value['state'] ?? null ) || ! is_string( $value['gateway'] ?? null ) || ! is_array( $value['identities'] ?? null ) ) {
			return null;
		}
		return $value;
	}

	/**
	 * Persist an updated payment-attempt state.
	 *
	 * @param array<string,mixed> $attempt Payment-attempt state.
	 */
	private function save_attempt( \WC_Order $order, array $attempt ): void {
		$order->update_meta_data( self::META_KEY, $attempt );
		$order->save_meta_data();
	}

	/**
	 * Decode a payment-attempt identity snapshot.
	 *
	 * @param array<mixed> $snapshot Stored identity snapshot.
	 * @return array<int,array<string,mixed>>
	 */
	private function decode_identities( array $snapshot ): array {
		$identities = array();
		foreach ( $snapshot as $type => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$decoded = array();
			foreach ( array( 'key_fingerprint', 'identifier_hash', 'active_key_fingerprint', 'active_key' ) as $field ) {
				$value  = $row[ $field ] ?? null;
				$binary = is_string( $value ) ? hex2bin( $value ) : false;
				if ( false === $binary ) {
					continue 2;
				}
				$decoded[ $field ] = $binary;
			}
			$identities[ (int) $type ] = array_merge( $row, $decoded );
		}
		return $identities;
	}
}
