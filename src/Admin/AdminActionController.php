<?php
/**
 * Capability- and nonce-protected M6 administration actions.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Operations\AttackStartMailer;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;
use Codeprint\CheckoutFirewall\Operations\IdentityMasker;
use Codeprint\CheckoutFirewall\Operations\RetentionPolicy;
use Codeprint\CheckoutFirewall\Protection\BlockRepository;
use Codeprint\CheckoutFirewall\Protection\ClientIpResolver;
use Codeprint\CheckoutFirewall\Protection\TrustedExemptionStore;
use Codeprint\CheckoutFirewall\Recaptcha\RecaptchaConfig;
use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Security\RequestNormalizer;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;

final class AdminActionController {
	public const NONCE_PREFIX = 'checkout_firewall_admin_';
	private const ACTIONS     = array(
		'start'     => 'checkout_firewall_start_emergency',
		'stop'      => 'checkout_firewall_stop_emergency',
		'block'     => 'checkout_firewall_create_block',
		'unblock'   => 'checkout_firewall_release_block',
		'settings'  => 'checkout_firewall_save_operations',
		'health'    => 'checkout_firewall_run_health',
		'rotate'    => 'checkout_firewall_rotate_key',
		'uninstall' => 'checkout_firewall_save_uninstall',
		'observe'   => 'checkout_firewall_enable_observe',
		'standard'  => 'checkout_firewall_enable_standard',
		'trust'     => 'checkout_firewall_create_exemption',
		'untrust'   => 'checkout_firewall_remove_exemption',
	);

	private EmergencyMode $mode;
	private AttackStartMailer $mailer;
	private OperatingMode $operating;
	private TrustedExemptionStore $exemptions;

	public function __construct( EmergencyMode $mode, AttackStartMailer $mailer, ?OperatingMode $operating = null, ?TrustedExemptionStore $exemptions = null ) {
		$this->mode       = $mode;
		$this->mailer     = $mailer;
		$this->operating  = $operating ?? new OperatingMode();
		$this->exemptions = $exemptions ?? new TrustedExemptionStore();
	}

	public function register(): void {
		foreach ( self::ACTIONS as $method => $action ) {
			add_action( 'admin_post_' . $action, array( $this, $method ) );
		}
	}

	public function start(): void {
		$this->authorize( self::ACTIONS['start'] );
		$duration = $this->post_int( 'duration' );
		$confirm  = $this->post_string( 'confirm', 8 );
		if ( '1' !== $confirm ) {
			$this->redirect( 'overview', 'confirmation_required' );
		}
		$state = array();
		try {
			$state = $this->mode->start( $duration );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'overview', 'emergency_unavailable' );
		}
		try {
			$this->mailer->queue( $state );
		} catch ( \Throwable $exception ) {
			Health::record( 'mail', 'queue_failed' );
		}
		$this->redirect( 'overview', 'emergency_started' );
	}

	public function stop(): void {
		$this->authorize( self::ACTIONS['stop'] );
		$this->mode->stop();
		$this->redirect( 'overview', 'emergency_stopped' );
	}

	public function observe(): void {
		$this->authorize( self::ACTIONS['observe'] );
		if ( $this->mode->is_active() ) {
			$this->redirect( 'overview', 'observe_refused' );
		}
		try {
			$this->operating->enter_observe();
			$this->redirect( 'overview', 'observe_enabled' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'overview', 'mode_failed' );
		}
	}

	public function standard(): void {
		$this->authorize( self::ACTIONS['standard'] );
		try {
			$this->operating->enter_standard();
			$this->redirect( 'overview', 'standard_enabled' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'overview', 'mode_failed' );
		}
	}

	public function trust(): void {
		$this->authorize( self::ACTIONS['trust'] );
		$type      = $this->post_string( 'exemption_type', 16 );
		$value     = $this->post_string( 'exemption_value', 254 );
		$reason    = $this->post_string( 'exemption_reason', 32 );
		$duration  = $this->post_string( 'exemption_duration', 16 );
		$durations = array(
			'86400'   => 86400,
			'604800'  => 604800,
			'2592000' => 2592000,
			'never'   => null,
		);
		try {
			if ( ! array_key_exists( $duration, $durations ) ) {
				throw new \InvalidArgumentException( 'Invalid exemption duration.' );
			}
			if ( 'ip' === $type ) {
				$this->exemptions->create_ip( $value, $reason, $durations[ $duration ] );
			} elseif ( 'user' === $type && ctype_digit( $value ) ) {
				$this->exemptions->create_user( (int) $value, $reason, $durations[ $duration ] );
			} else {
				throw new \InvalidArgumentException( 'Invalid exemption subject.' );
			}
			$this->redirect( 'blocks', 'exemption_created' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'blocks', 'exemption_invalid' );
		}
	}

	public function untrust(): void {
		$id = $this->post_string( 'exemption_id', 32 ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Exact row-bound nonce is verified next.
		$this->authorize_exemption( $id );
		try {
			$this->redirect( 'blocks', $this->exemptions->remove( $id ) ? 'exemption_removed' : 'exemption_inactive' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'blocks', 'exemption_remove_failed' );
		}
	}

	public function block(): void {
		$this->authorize( self::ACTIONS['block'] );
		$type     = $this->post_string( 'identifier_type', 16 );
		$value    = $this->post_string( 'identifier', 254 );
		$duration = $this->post_string( 'block_duration', 16 );
		try {
			if ( 'ip' === $type ) {
				$packed = inet_pton( $value );
				if ( false === $packed ) {
					throw new \InvalidArgumentException( 'Invalid IP.' );
				}
				$canonical = inet_ntop( $packed );
				if ( false === $canonical ) {
					throw new \InvalidArgumentException( 'Invalid IP.' );
				}
				$canonical = strtolower( $canonical );
				$id_type   = IdentifierType::IP;
				$hint      = IdentityMasker::ip( $canonical );
			} elseif ( 'email' === $type ) {
				$canonical = strtolower( trim( sanitize_email( $value ) ) );
				if ( '' === $canonical || ! is_email( $canonical ) ) {
					throw new \InvalidArgumentException( 'Invalid email.' );
				}
				$id_type = IdentifierType::EMAIL;
				$hint    = IdentityMasker::email( $canonical );
			} else {
				throw new \InvalidArgumentException( 'Invalid block type.' );
			}
			$durations = array(
				'3600'   => 3600,
				'86400'  => 86400,
				'604800' => 604800,
				'never'  => null,
			);
			if ( ! array_key_exists( $duration, $durations ) ) {
				throw new \InvalidArgumentException( 'Invalid block duration.' );
			}
			$keys     = new KeyStore();
			$identity = array_merge(
				array(
					'identifier_type' => $id_type,
					'display_hint'    => $hint,
				),
				$keys->hash_identifier( $id_type, $canonical ),
				$keys->active_key( $id_type, $canonical )
			);
			( new BlockRepository() )->create_manual( $identity, $hint, $durations[ $duration ] );
			$this->redirect( 'blocks', 'block_created' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'blocks', 'block_invalid' );
		}
	}

	public function unblock(): void {
		$id = $this->post_int( 'block_id' ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Selects the row-bound nonce verified next.
		$this->authorize( self::ACTIONS['unblock'], $id );
		try {
			$released = ( new BlockRepository() )->release_id( $id );
			$this->redirect( 'blocks', $released ? 'block_released' : 'block_inactive' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'blocks', 'block_release_failed' );
		}
	}

	public function settings(): void {
		$this->authorize( self::ACTIONS['settings'] );
		$enabled   = '1' === $this->post_string( 'email_enabled', 1 ) ? '1' : '0';
		$recipient = sanitize_email( $this->post_string( 'email_recipient', 254 ) );
		if ( '' === $recipient || ! is_email( $recipient ) ) {
			$this->redirect( 'settings', 'settings_invalid' );
		}
		$event   = $this->post_int( 'event_retention' );
		$history = $this->post_int( 'history_retention' );
		$hint    = $this->post_int( 'hint_retention' );
		$mode    = $this->post_string( 'proxy_mode', 16 );
		$header  = $this->post_string( 'proxy_header', 32 );
		$raw     = $this->post_string( 'proxy_cidrs', 4096 );
		$lines   = preg_split( '/\r\n|\r|\n/', $raw );
		$cidrs   = array_values( array_filter( array_map( 'trim', false === $lines ? array() : $lines ), static fn( string $line ): bool => '' !== $line ) );
		try {
			$resolver = new ClientIpResolver();
			$resolver->validate_policy( $mode, $header, $cidrs );
			if ( ! RetentionPolicy::accepts( $event, array( 1, 3, 7 ) )
				|| ! RetentionPolicy::accepts( $history, array( 1, 3, 7 ) )
				|| ! RetentionPolicy::accepts( $hint, array( 7, 30, 90 ) )
			) {
				throw new \InvalidArgumentException( 'Invalid retention.' );
			}
			RetentionPolicy::save( RetentionPolicy::EVENT_OPTION, $event, array( 1, 3, 7 ) );
			RetentionPolicy::save( RetentionPolicy::HISTORY_OPTION, $history, array( 1, 3, 7 ) );
			RetentionPolicy::save( RetentionPolicy::HINT_OPTION, $hint, array( 7, 30, 90 ) );
			$resolver->save_policy( $mode, $header, $cidrs );
			self::write( AttackStartMailer::ENABLED_OPTION, $enabled );
			self::write( AttackStartMailer::RECIPIENT_OPTION, $recipient );
			$this->redirect( 'settings', 'settings_saved' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'settings', 'settings_invalid' );
		}
	}

	public function health(): void {
		$this->authorize( self::ACTIONS['health'] );
		try {
			( new HealthReport() )->run();
			$this->redirect( 'overview', 'health_checked' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'overview', 'health_failed' );
		}
	}

	public function rotate(): void {
		$this->authorize( self::ACTIONS['rotate'] );
		if ( $this->mode->is_active() || 'ROTATE' !== $this->post_string( 'confirmation', 16 ) ) {
			$this->redirect( 'settings', 'rotation_refused' );
		}
		try {
			( new KeyStore() )->rotate_identifier_key();
			( new TurnstileConfig() )->invalidate();
			( new RecaptchaConfig() )->invalidate();
			$this->redirect( 'settings', 'key_rotated' );
		} catch ( \Throwable $exception ) {
			$this->redirect( 'settings', 'rotation_failed' );
		}
	}

	public function uninstall(): void {
		$this->authorize( self::ACTIONS['uninstall'] );
		if ( defined( 'CHECKOUT_FIREWALL_DELETE_DATA_ON_UNINSTALL' ) && true === CHECKOUT_FIREWALL_DELETE_DATA_ON_UNINSTALL ) {
			$this->redirect( 'privacy', 'uninstall_constant' );
		}
		$choice = $this->post_string( 'uninstall_data', 16 );
		if ( ! in_array( $choice, array( 'preserve', 'delete' ), true ) ) {
			$this->redirect( 'privacy', 'settings_invalid' );
		}
		if ( 'delete' === $choice && 'DELETE' !== $this->post_string( 'confirmation', 16 ) ) {
			$this->redirect( 'privacy', 'confirmation_required' );
		}
		self::write( 'checkout_firewall_delete_data_on_uninstall', 'delete' === $choice ? '1' : '0' );
		$this->redirect( 'privacy', 'uninstall_saved' );
	}

	public static function nonce_action( string $action, int $row_id = 0 ): string {
		return self::NONCE_PREFIX . sanitize_key( $action ) . ( $row_id > 0 ? '_' . $row_id : '' );
	}

	private function authorize( string $action, int $row_id = 0 ): void {
		if ( 'POST' !== RequestNormalizer::request_method() || ! current_user_can( 'manage_woocommerce' ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Checkout Firewall.', 'checkout-firewall' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::nonce_action( $action, $row_id ) );
	}

	private function authorize_exemption( string $id ): void {
		if ( 'POST' !== RequestNormalizer::request_method() || ! current_user_can( 'manage_woocommerce' ) || 1 !== preg_match( '/^[a-f0-9]{32}$/D', $id ) ) {
			wp_die( esc_html__( 'You are not allowed to manage Checkout Firewall.', 'checkout-firewall' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::exemption_nonce_action( $id ) );
	}

	public static function exemption_nonce_action( string $id ): string {
		return self::NONCE_PREFIX . self::ACTIONS['untrust'] . '_' . $id;
	}

	private function post_string( string $key, int $limit ): string {
		$value = 'proxy_cidrs' === $key ? RequestNormalizer::post_textarea( $key, $limit ) : RequestNormalizer::post( $key, $limit );
		return $value['invalid'] || null === $value['value'] ? '' : $value['value'];
	}

	private function post_int( string $key ): int {
		return absint( $this->post_string( $key, 16 ) );
	}

	private function redirect( string $view, string $status ): void {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'                     => CheckoutFirewallPage::SLUG,
					'view'                     => $view,
					'checkout_firewall_status' => sanitize_key( $status ),
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Persist one non-autoloaded option.
	 *
	 * @param mixed $value Option value.
	 */
	private static function write( string $option, $value ): void {
		if ( false === get_option( $option, false ) ) {
			add_option( $option, $value, '', false );
			return;
		}
		update_option( $option, $value, false );
	}
}
