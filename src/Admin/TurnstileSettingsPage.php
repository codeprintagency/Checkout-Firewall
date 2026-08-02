<?php
/**
 * Narrow M5 WooCommerce Turnstile settings surface.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConflictDetector;

final class TurnstileSettingsPage {
	public const SLUG = 'checkout-firewall';
	private TurnstileConfig $config;
	private TurnstileConflictDetector $conflicts;

	public function __construct( TurnstileConfig $config, TurnstileConflictDetector $conflicts ) {
		$this->config    = $config;
		$this->conflicts = $conflicts;
	}

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
	}

	public function menu(): void {
		add_submenu_page( 'woocommerce', __( 'Checkout Firewall', 'checkout-firewall' ), __( 'Checkout Firewall', 'checkout-firewall' ), 'manage_woocommerce', self::SLUG, array( $this, 'render' ) );
	}

	public function assets( string $hook ): void {
		if ( 'woocommerce_page_' . self::SLUG !== $hook ) {
			return;
		}
		wp_enqueue_style( 'checkout-firewall-admin', plugins_url( 'assets/css/checkout-firewall-admin.css', CWF_PLUGIN_FILE ), array(), CWF_VERSION );
		wp_enqueue_script( 'checkout-firewall-turnstile-admin', plugins_url( 'assets/js/checkout-turnstile-admin.js', CWF_PLUGIN_FILE ), array(), CWF_VERSION, true );
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			return;
		}
		$credentials = $this->config->credentials();
		$status      = isset( $_GET['cwf_status'] ) && is_string( $_GET['cwf_status'] ) ? sanitize_key( wp_unslash( $_GET['cwf_status'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display-only status slug.
		$conflict    = $this->conflicts->active_slug();
		$test_pair   = TurnstileConfig::is_test_pair( $credentials );
		?>
		<div class="wrap cf-admin">
			<header class="cf-admin__header"><p class="cf-eyebrow"><?php esc_html_e( 'CHECKOUT FIREWALL', 'checkout-firewall' ); ?></p><h1><?php esc_html_e( 'Turnstile recovery', 'checkout-firewall' ); ?></h1><p><?php esc_html_e( 'Ask for an extra check only when local checkout protection needs it.', 'checkout-firewall' ); ?></p></header>
			<?php
			if ( '' !== $status ) :
				?>
				<div class="cf-notice" role="status"><?php echo esc_html( self::status_copy( $status ) ); ?></div><?php endif; ?>
			<?php
			if ( null !== $conflict ) :
				?>
				<div class="cf-notice cf-notice--challenge"><strong><?php esc_html_e( 'Turnstile conflict', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Another CAPTCHA plugin is active on checkout. Two challenges on one form frustrate customers. Disable one — check the Plugins screen.', 'checkout-firewall' ); ?></p></div><?php endif; ?>
			<section class="cf-card" aria-labelledby="cf-turnstile-title">
				<div class="cf-card__heading"><div><p class="cf-eyebrow"><?php echo $test_pair ? esc_html__( 'TEST KEYS · NOT FOR PRODUCTION', 'checkout-firewall' ) : ( $this->config->is_active() ? esc_html__( 'VERIFIED · ACTIVE', 'checkout-firewall' ) : esc_html__( 'SETUP REQUIRED', 'checkout-firewall' ) ); ?></p><h2 id="cf-turnstile-title"><?php esc_html_e( 'Cloudflare Turnstile', 'checkout-firewall' ); ?></h2></div></div>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="<?php echo esc_attr( TurnstileSettingsController::SAVE_ACTION ); ?>" /><?php wp_nonce_field( TurnstileSettingsController::NONCE_ACTION ); ?>
					<label for="cwf-site-key"><?php esc_html_e( 'Site key', 'checkout-firewall' ); ?></label><input id="cwf-site-key" name="site_key" type="text" maxlength="128" value="<?php echo esc_attr( $credentials['site_key'] ); ?>" autocomplete="off" required <?php wp_readonly( defined( 'CWF_TURNSTILE_SITE_KEY' ) ); ?> />
					<label for="cwf-secret-key"><?php esc_html_e( 'Secret key', 'checkout-firewall' ); ?></label><input id="cwf-secret-key" name="secret_key" type="password" maxlength="256" value="" autocomplete="new-password" placeholder="<?php echo defined( 'CWF_TURNSTILE_SECRET_KEY' ) ? esc_attr__( 'Configured in wp-config.php', 'checkout-firewall' ) : ( '' === $credentials['secret_key'] ? esc_attr__( 'Required', 'checkout-firewall' ) : esc_attr__( 'Saved — leave blank to keep it', 'checkout-firewall' ) ); ?>" <?php wp_readonly( defined( 'CWF_TURNSTILE_SECRET_KEY' ) ); ?> />
					<?php if ( defined( 'CWF_TURNSTILE_SITE_KEY' ) || defined( 'CWF_TURNSTILE_SECRET_KEY' ) ) : ?>
						<p class="cf-help" id="cwf-key-source"><?php esc_html_e( 'Read-only keys are supplied by wp-config.php and are never copied into WordPress options.', 'checkout-firewall' ); ?></p>
					<?php endif; ?>
					<p class="cf-help"><?php esc_html_e( 'Keys are stored without autoload. Saving a change disables recovery until it is verified again.', 'checkout-firewall' ); ?></p>
					<p class="cf-help"><?php esc_html_e( 'Express-payment recovery is not yet tested for this store. If a payment sheet is interrupted, use the standard checkout button.', 'checkout-firewall' ); ?></p>
					<div class="cf-actions"><button class="button button-primary cf-button" type="submit"><?php esc_html_e( 'Save keys', 'checkout-firewall' ); ?></button>
					<?php
					if ( '' !== $credentials['site_key'] ) :
						?>
						<button class="button cf-button" type="submit" name="remove" value="1"><?php esc_html_e( 'Remove keys', 'checkout-firewall' ); ?></button><?php endif; ?></div>
				</form>
				<?php if ( '' !== $credentials['site_key'] && '' !== $credentials['secret_key'] && null === $conflict ) : ?>
				<form class="cf-health" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-site-key="<?php echo esc_attr( $credentials['site_key'] ); ?>" data-action="checkout_firewall_health" data-cdata="<?php echo esc_attr( $this->config->health_cdata() ); ?>">
					<input type="hidden" name="action" value="<?php echo esc_attr( TurnstileSettingsController::VERIFY_ACTION ); ?>" /><?php wp_nonce_field( TurnstileSettingsController::NONCE_ACTION ); ?><input type="hidden" name="health_token" value="" /><div class="cf-health__widget" aria-live="polite"></div><button class="button button-primary cf-button" type="button" data-cf-verify disabled><?php esc_html_e( 'Verify and activate', 'checkout-firewall' ); ?></button>
				</form>
				<?php endif; ?>
			</section>
			<p class="cf-legal"><?php esc_html_e( 'Checkout Firewall is an independent product by Codeprint. WooCommerce and Cloudflare are trademarks of their respective owners.', 'checkout-firewall' ); ?></p>
		</div>
		<?php
	}

	private static function status_copy( string $status ): string {
		$copy = array(
			'saved'               => __( 'Keys saved. Complete verification to activate Turnstile recovery.', 'checkout-firewall' ),
			'removed'             => __( 'Turnstile keys were removed.', 'checkout-firewall' ),
			'verified'            => __( 'Turnstile recovery is verified and active.', 'checkout-firewall' ),
			'invalid'             => __( 'The keys were not saved. Check their format and try again.', 'checkout-firewall' ),
			'invalid_secret'      => __( 'Cloudflare rejected the secret. Turnstile recovery remains disabled.', 'checkout-firewall' ),
			'verification_failed' => __( 'Verification did not complete. Turnstile recovery remains disabled.', 'checkout-firewall' ),
			'test_keys'           => __( 'Cloudflare test keys are allowed only in local, development, or test environments.', 'checkout-firewall' ),
		);
		return $copy[ $status ] ?? __( 'Settings updated.', 'checkout-firewall' );
	}
}
