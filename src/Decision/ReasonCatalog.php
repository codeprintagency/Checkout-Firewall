<?php
/**
 * First-party decision reason metadata and copy.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Decision;

final class ReasonCatalog {
	public const VERSION = 1;
	/**
	 * Request-local extension reasons.
	 *
	 * @var array<string,array{action:string,explanation:\Closure():string}>
	 */
	private static array $extensions = array();

	public static function register_extension( string $reason, string $action, callable $explanation ): bool {
		if ( 1 === count( self::$extensions ) || 1 !== preg_match( '/^[A-Z][A-Z0-9_]{0,63}$/D', $reason )
			|| self::has( $reason ) || ! in_array( $action, array( DecisionAction::ALLOW, DecisionAction::CHALLENGE, DecisionAction::BLOCK ), true )
		) {
			return false;
		}
		self::$extensions[ $reason ] = array(
			'action'      => $action,
			'explanation' => \Closure::fromCallable( $explanation ),
		);
		return true;
	}

	/**
	 * Return the action assigned to every stable reason.
	 *
	 * @return array<string,string>
	 */
	private static function actions(): array {
		return array(
			ReasonCode::CHECKOUT_ALLOWED           => DecisionAction::ALLOW,
			ReasonCode::EXPLICIT_LOCAL_BLOCK       => DecisionAction::BLOCK,
			ReasonCode::FLOW_PROOF_REPLAYED        => DecisionAction::BLOCK,
			ReasonCode::FLOW_PROOF_INVALID         => DecisionAction::BLOCK,
			ReasonCode::PAYMENT_FAILURE_LOCKOUT    => DecisionAction::BLOCK,
			ReasonCode::VELOCITY_THROTTLED         => DecisionAction::BLOCK,
			ReasonCode::EMERGENCY_MODE             => DecisionAction::BLOCK,
			ReasonCode::VELOCITY_COMBINED_EXCEEDED => DecisionAction::CHALLENGE,
			ReasonCode::VELOCITY_SESSION_EXCEEDED  => DecisionAction::CHALLENGE,
			ReasonCode::VELOCITY_EMAIL_EXCEEDED    => DecisionAction::CHALLENGE,
			ReasonCode::VELOCITY_IP_EXCEEDED       => DecisionAction::CHALLENGE,
			ReasonCode::PAYMENT_FAILURE_CHALLENGE  => DecisionAction::CHALLENGE,
			ReasonCode::AUTOMATION_EVIDENCE        => DecisionAction::CHALLENGE,
			ReasonCode::TURNSTILE_INVALID          => DecisionAction::CHALLENGE,
			ReasonCode::TURNSTILE_REQUIRED         => DecisionAction::CHALLENGE,
			ReasonCode::CHALLENGE_INVALID          => DecisionAction::CHALLENGE,
			ReasonCode::CHALLENGE_REQUIRED         => DecisionAction::CHALLENGE,
			ReasonCode::CHALLENGE_UNAVAILABLE      => DecisionAction::BLOCK,
			ReasonCode::FLOW_PROOF_EXPIRED         => DecisionAction::CHALLENGE,
			ReasonCode::FLOW_PROOF_MISSING         => DecisionAction::CHALLENGE,
			ReasonCode::TRUSTED_CUSTOMER_REDUCTION => DecisionAction::ALLOW,
			ReasonCode::GATEWAY_OUTAGE_OVERRIDE    => DecisionAction::ALLOW,
			ReasonCode::INTERNAL_ERROR_FAIL_OPEN   => DecisionAction::ALLOW,
		);
	}

	public static function has( string $reason ): bool {
		return isset( self::actions()[ $reason ] ) || isset( self::$extensions[ $reason ] );
	}

	public static function action( string $reason ): string {
		$actions = self::actions();
		if ( isset( self::$extensions[ $reason ] ) ) {
			return self::$extensions[ $reason ]['action'];
		}
		if ( ! isset( $actions[ $reason ] ) ) {
			throw new \InvalidArgumentException( 'Unknown checkout decision reason.' );
		}
		return $actions[ $reason ];
	}

	public static function admin_explanation( string $reason ): string {
		switch ( $reason ) {
			case ReasonCode::CHECKOUT_ALLOWED:
				return __( 'No protection rule requested an intervention.', 'checkout-firewall' );
			case ReasonCode::EXPLICIT_LOCAL_BLOCK:
				return __( 'A local block explicitly denied this checkout.', 'checkout-firewall' );
			case ReasonCode::FLOW_PROOF_REPLAYED:
				return __( 'The checkout-flow proof was already consumed.', 'checkout-firewall' );
			case ReasonCode::FLOW_PROOF_INVALID:
				return __( 'The checkout-flow proof was invalid.', 'checkout-firewall' );
			case ReasonCode::PAYMENT_FAILURE_LOCKOUT:
				return __( 'Recent payment failures reached the local lockout policy.', 'checkout-firewall' );
			case ReasonCode::VELOCITY_THROTTLED:
				return __( 'Checkout velocity reached the temporary local throttle policy.', 'checkout-firewall' );
			case ReasonCode::EMERGENCY_MODE:
				return __( 'Merchant-enabled Emergency Mode denied this checkout.', 'checkout-firewall' );
			case ReasonCode::VELOCITY_COMBINED_EXCEEDED:
				return __( 'Combined local checkout velocity exceeded its threshold.', 'checkout-firewall' );
			case ReasonCode::VELOCITY_SESSION_EXCEEDED:
				return __( 'Session checkout velocity exceeded its threshold.', 'checkout-firewall' );
			case ReasonCode::VELOCITY_EMAIL_EXCEEDED:
				return __( 'Email checkout velocity exceeded its threshold.', 'checkout-firewall' );
			case ReasonCode::VELOCITY_IP_EXCEEDED:
				return __( 'IP checkout velocity exceeded its threshold.', 'checkout-firewall' );
			case ReasonCode::PAYMENT_FAILURE_CHALLENGE:
				return __( 'Recent attributable payment failures requested an extra checkout check before the next gateway attempt.', 'checkout-firewall' );
			case ReasonCode::AUTOMATION_EVIDENCE:
				return __( 'Multiple bounded browser-automation signals requested an extra checkout check.', 'checkout-firewall' );
			case ReasonCode::TURNSTILE_INVALID:
				return __( 'The configured Turnstile challenge was invalid.', 'checkout-firewall' );
			case ReasonCode::TURNSTILE_REQUIRED:
				return __( 'The configured Turnstile challenge is required.', 'checkout-firewall' );
			case ReasonCode::CHALLENGE_INVALID:
				return __( 'The selected checkout challenge was invalid.', 'checkout-firewall' );
			case ReasonCode::CHALLENGE_REQUIRED:
				return __( 'The selected checkout challenge is required.', 'checkout-firewall' );
			case ReasonCode::CHALLENGE_UNAVAILABLE:
				return __( 'A recoverable checkout limit was reached while challenge recovery was unavailable.', 'checkout-firewall' );
			case ReasonCode::FLOW_PROOF_EXPIRED:
				return __( 'The checkout-flow proof expired.', 'checkout-firewall' );
			case ReasonCode::FLOW_PROOF_MISSING:
				return __( 'The checkout-flow proof was missing.', 'checkout-firewall' );
			case ReasonCode::TRUSTED_CUSTOMER_REDUCTION:
				return __( 'Trusted-customer policy reduced the intervention before evaluation.', 'checkout-firewall' );
			case ReasonCode::GATEWAY_OUTAGE_OVERRIDE:
				return __( 'Gateway-outage policy reduced the intervention before evaluation.', 'checkout-firewall' );
			case ReasonCode::INTERNAL_ERROR_FAIL_OPEN:
				return __( 'Checkout Firewall encountered an internal error and failed open.', 'checkout-firewall' );
			default:
				if ( isset( self::$extensions[ $reason ] ) ) {
					$explanation = ( self::$extensions[ $reason ]['explanation'] )();
					if ( '' !== $explanation && strlen( $explanation ) <= 512 ) {
						return $explanation;
					}
				}
				throw new \InvalidArgumentException( 'Unknown checkout decision reason.' );
		}
	}

	public static function customer_message( string $action, string $reason = '' ): string {
		if ( in_array( $reason, array( ReasonCode::CHALLENGE_UNAVAILABLE, ReasonCode::VELOCITY_THROTTLED ), true ) ) {
			return __( 'Too many checkout attempts were made. Please wait a few minutes and try again.', 'checkout-firewall' );
		}
		if ( DecisionAction::CHALLENGE === $action ) {
			return __( 'Please verify your checkout and try again.', 'checkout-firewall' );
		}
		if ( DecisionAction::BLOCK === $action ) {
			return __( 'This checkout could not be processed. Contact the store if you believe this is an error.', 'checkout-firewall' );
		}
		return '';
	}

	public static function priority( string $reason ): int {
		if ( ReasonCode::CHECKOUT_ALLOWED === $reason ) {
			return 0;
		}
		if ( isset( self::$extensions[ $reason ] ) ) {
			return 1;
		}

		$position = array_search( $reason, ReasonCode::all(), true );
		if ( false === $position ) {
			throw new \InvalidArgumentException( 'Unknown checkout decision reason.' );
		}
		return count( ReasonCode::all() ) - (int) $position + 1;
	}

	public static function clear_extensions_for_test(): void {
		self::$extensions = array();
	}
}
