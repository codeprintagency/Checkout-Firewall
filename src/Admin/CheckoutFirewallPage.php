<?php
/**
 * Single Free Checkout Firewall administration surface.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Challenge\ChallengePolicy;
use Codeprint\CheckoutFirewall\Decision\ReasonCatalog;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Commercial\CommercialAccountController;
use Codeprint\CheckoutFirewall\Commercial\CommercialBootstrap;
use Codeprint\CheckoutFirewall\Operations\AttackStartMailer;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;
use Codeprint\CheckoutFirewall\Operations\IdentityMasker;
use Codeprint\CheckoutFirewall\Operations\RetentionPolicy;
use Codeprint\CheckoutFirewall\Protection\BlockRepository;
use Codeprint\CheckoutFirewall\Protection\ClientIpResolver;
use Codeprint\CheckoutFirewall\Protection\EventRepository;
use Codeprint\CheckoutFirewall\Protection\TrustedExemptionStore;
use Codeprint\CheckoutFirewall\Recaptcha\RecaptchaConfig;
use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConflictDetector;

final class CheckoutFirewallPage {
	public const SLUG   = 'checkout-firewall';
	private const VIEWS = array( 'overview', 'activity', 'blocks', 'settings', 'privacy' );
	private TurnstileConfig $turnstile;
	private TurnstileConflictDetector $conflicts;
	private EmergencyMode $mode;
	private ChallengeConfig $challenges;
	private RecaptchaConfig $recaptcha;
	private OperatingMode $operating;
	private TrustedExemptionStore $exemptions;
	private ChallengePolicy $challenge_policy;

	public function __construct( TurnstileConfig $turnstile, TurnstileConflictDetector $conflicts, EmergencyMode $mode, ?ChallengeConfig $challenges = null, ?RecaptchaConfig $recaptcha = null, ?OperatingMode $operating = null, ?TrustedExemptionStore $exemptions = null, ?ChallengePolicy $challenge_policy = null ) {
		$this->turnstile        = $turnstile;
		$this->conflicts        = $conflicts;
		$this->mode             = $mode;
		$this->recaptcha        = $recaptcha ?? new RecaptchaConfig();
		$this->challenges       = $challenges ?? new ChallengeConfig( $turnstile, $this->recaptcha, $conflicts );
		$this->operating        = $operating ?? new OperatingMode();
		$this->exemptions       = $exemptions ?? new TrustedExemptionStore();
		$this->challenge_policy = $challenge_policy ?? new ChallengePolicy();
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
		wp_enqueue_style( 'checkout-firewall-admin', plugins_url( 'assets/css/checkout-firewall-admin.css', CHECKOUT_FIREWALL_PLUGIN_FILE ), array(), CHECKOUT_FIREWALL_VERSION );
		wp_enqueue_script( 'checkout-firewall-admin', plugins_url( 'assets/js/checkout-firewall-admin.js', CHECKOUT_FIREWALL_PLUGIN_FILE ), array(), CHECKOUT_FIREWALL_VERSION, true );
		if ( 'settings' === $this->view() ) {
			wp_enqueue_script( 'checkout-firewall-turnstile-admin', plugins_url( 'assets/js/checkout-turnstile-admin.js', CHECKOUT_FIREWALL_PLUGIN_FILE ), array(), CHECKOUT_FIREWALL_VERSION, true );
			wp_enqueue_script( 'checkout-firewall-recaptcha-admin', plugins_url( 'assets/js/checkout-recaptcha-admin.js', CHECKOUT_FIREWALL_PLUGIN_FILE ), array(), CHECKOUT_FIREWALL_VERSION, true );
		}
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			return;
		}
		$view         = $this->view();
		$status_input = \Codeprint\CheckoutFirewall\Security\RequestNormalizer::query( 'checkout_firewall_status', 64, '/^[a-z0-9_-]+$/D' );
		$status       = $status_input['invalid'] || null === $status_input['value'] ? '' : $status_input['value'];
		$license      = AdminExtensionRegistry::license_label();
		?>
			<div class="wrap cf-admin">
				<header class="cf-admin__header">
					<div class="cf-brand"><span class="cf-brand__mark" aria-hidden="true"><span>›</span>cf</span><h1><span>Checkout</span><strong>Firewall</strong></h1></div>
					<span class="cf-mode-badge <?php echo $this->mode->is_active() ? 'cf-mode-badge--emergency' : ( $this->operating->is_observing() ? 'cf-mode-badge--observe' : 'cf-mode-badge--standard' ); ?>"><?php echo $this->mode->is_active() ? esc_html__( 'EMERGENCY MODE', 'checkout-firewall' ) : ( $this->operating->is_observing() ? esc_html__( 'OBSERVE MODE', 'checkout-firewall' ) : esc_html__( 'STANDARD MODE', 'checkout-firewall' ) ); ?></span>
					<span class="cf-admin__license <?php echo '' === $license ? '' : 'cf-admin__license--premium'; ?>">
					<?php if ( '' === $license ) : ?>
						<?php esc_html_e( 'Free · local protection', 'checkout-firewall' ); ?>
					<?php else : ?>
						<span class="cf-premium-badge"><span aria-hidden="true">◆</span><?php esc_html_e( 'Premium', 'checkout-firewall' ); ?></span><span><?php echo esc_html( $license ); ?></span>
					<?php endif; ?>
					</span>
				</header>
				<?php $this->nav( $view ); ?>
				<main class="cf-admin__content">
			<?php
			if ( '' !== $status ) :
				?>
				<div class="cf-notice" role="status"><?php echo esc_html( $this->status_copy( $status ) ); ?></div><?php endif; ?>
			<?php
			switch ( $view ) {
				case 'activity':
					$this->activity();
					break;
				case 'blocks':
					$this->blocks();
					break;
				case 'settings':
					$this->settings();
					break;
				case 'privacy':
					$this->privacy();
					break;
				default:
					$this->overview();
			}
					$this->legal();
			?>
				</main>
				</div>
			<?php
	}

	private function overview(): void {
		$active          = $this->mode->is_active();
		$observing       = $this->operating->is_observing();
		$operating_state = $this->operating->state();
		$state           = $this->mode->state();
		$conflict        = $this->conflicts->has_conflict();
		$recovery_ready  = $this->challenges->is_available();
		$recent          = $this->recent_events( 6 );
		$summary         = $this->event_summary();
		$attention_title = '';
		$attention_body  = '';
		$attention_url   = '';
		$attention_cta   = '';
		if ( $conflict ) {
			$attention_title = __( 'Two checkout challenges may be running.', 'checkout-firewall' );
			$attention_body  = __( 'Another CAPTCHA plugin appears to be active. Customers may see conflicting challenges until one integration is disabled.', 'checkout-firewall' );
			$attention_url   = $this->view_url( 'settings' );
			$attention_cta   = __( 'Review the conflict', 'checkout-firewall' );
		}
		?>
		<?php if ( '' !== $attention_title && ! $active ) : ?>
			<div class="cf-action-needed" role="status"><div><strong><?php echo esc_html( $attention_title ); ?></strong><p><?php echo esc_html( $attention_body ); ?></p></div><a class="cf-button cf-button--primary" href="<?php echo esc_url( $attention_url ); ?>"><?php echo esc_html( $attention_cta ); ?></a></div>
		<?php endif; ?>

		<section class="cf-protection-hero <?php echo $active ? 'cf-protection-hero--emergency' : ( $observing || ! $recovery_ready ? 'cf-protection-hero--reduced' : '' ); ?>" aria-labelledby="cf-protection-title">
			<div class="cf-protection-hero__copy">
				<p class="cf-eyebrow"><?php echo $active ? esc_html__( 'EMERGENCY MODE ACTIVE', 'checkout-firewall' ) : ( $observing ? esc_html__( 'OBSERVE MODE · NOT ENFORCING', 'checkout-firewall' ) : ( $recovery_ready ? esc_html__( 'PROTECTION ACTIVE', 'checkout-firewall' ) : esc_html__( 'PROTECTION ACTIVE · RECOVERY LIMITED', 'checkout-firewall' ) ) ); ?></p>
				<h2 id="cf-protection-title"><?php echo $active ? esc_html__( 'Every guest checkout requires fresh verification.', 'checkout-firewall' ) : ( $observing ? esc_html__( 'Observe Mode is measuring checkout activity.', 'checkout-firewall' ) : esc_html__( 'Checkout protection is active across your store.', 'checkout-firewall' ) ); ?></h2>
				<p><?php echo $active ? esc_html__( 'Guests must present valid checkout-flow proof and pass a fresh checkout challenge. Logged-in customers remain on Standard Mode, and no payment gateway has been changed.', 'checkout-firewall' ) : ( $observing ? esc_html__( 'Checkout Firewall is not challenging or stopping checkout attempts. Review what it would have done, then turn on Standard Mode when you are ready.', 'checkout-firewall' ) : esc_html__( 'Classic Checkout, Checkout Blocks, and Store API checkout routes are evaluated locally before payment processing.', 'checkout-firewall' ) ); ?></p>
				<div class="cf-surface-list" aria-label="<?php esc_attr_e( 'Protected checkout surfaces', 'checkout-firewall' ); ?>"><span><?php esc_html_e( 'CLASSIC CHECKOUT', 'checkout-firewall' ); ?></span><span><?php esc_html_e( 'CHECKOUT BLOCKS', 'checkout-firewall' ); ?></span><span><?php esc_html_e( 'STORE API', 'checkout-firewall' ); ?></span></div>
					<?php
					if ( $active && null !== $state ) :
						/* translators: 1: hours remaining, 2: minutes remaining. */
						$expiry_template = __( 'It expires in %1$d h %2$d m.', 'checkout-firewall' );
						?>
						<p class="cf-hero-meta" data-cf-emergency-expiry data-expiry="<?php echo esc_attr( gmdate( 'c', (int) strtotime( (string) $state['expires_at_gmt'] . ' UTC' ) ) ); ?>" data-template="<?php echo esc_attr( $expiry_template ); ?>"><?php echo esc_html( $this->remaining( (string) $state['expires_at_gmt'] ) ); ?></p><?php endif; ?>
			</div>
			<div class="cf-protection-hero__actions">
				<?php if ( $observing ) : ?>
					<?php $this->form_open( 'checkout_firewall_enable_standard' ); ?><button class="cf-button cf-button--primary" type="submit"><?php esc_html_e( 'Turn on Standard Mode', 'checkout-firewall' ); ?></button></form>
					<?php if ( null !== $operating_state ) : ?>
						<p class="cf-hero-meta"><?php /* translators: %s: advisory Observe Mode review date in UTC. */ printf( esc_html__( 'Review after %s UTC.', 'checkout-firewall' ), esc_html( (string) $operating_state['review_after_gmt'] ) ); ?></p>
					<?php endif; ?>
					<p><?php esc_html_e( 'Enforcement starts only when you choose it. The seven-day review date never turns protection on automatically.', 'checkout-firewall' ); ?></p>
				<?php else : ?>
					<?php $this->form_open( 'checkout_firewall_run_health' ); ?><button class="cf-button cf-button--secondary" type="submit"><?php esc_html_e( 'Run a protection check', 'checkout-firewall' ); ?></button></form>
					<?php if ( $active ) : ?>
						<?php $this->form_open( 'checkout_firewall_stop_emergency' ); ?><button class="cf-button cf-button--danger" type="submit"><?php esc_html_e( 'End Emergency Mode', 'checkout-firewall' ); ?></button></form>
				<?php else : ?>
					<?php $this->form_open( 'checkout_firewall_start_emergency' ); ?><label for="cf-duration" class="screen-reader-text"><?php esc_html_e( 'Emergency duration', 'checkout-firewall' ); ?></label><select id="cf-duration" name="duration"><option value="3600"><?php esc_html_e( '1 hour', 'checkout-firewall' ); ?></option><option value="14400" selected><?php esc_html_e( '4 hours', 'checkout-firewall' ); ?></option><option value="43200"><?php esc_html_e( '12 hours', 'checkout-firewall' ); ?></option><option value="86400"><?php esc_html_e( '24 hours', 'checkout-firewall' ); ?></option></select><input type="hidden" name="confirm" value="1" /><button class="cf-button cf-button--danger-outline" type="submit" <?php disabled( ! $recovery_ready ); ?>><?php esc_html_e( 'Turn on Emergency Mode', 'checkout-firewall' ); ?></button></form>
				<?php endif; ?>
				<p><?php esc_html_e( 'Emergency Mode challenges every guest checkout for a fixed period. It never disables a payment gateway.', 'checkout-firewall' ); ?></p>
					<?php
					if ( ! $active ) :
						?>
						<?php $this->form_open( 'checkout_firewall_enable_observe' ); ?><button class="cf-button cf-button--secondary cf-button--small" type="submit"><?php esc_html_e( 'Switch to Observe Mode', 'checkout-firewall' ); ?></button></form><?php endif; ?>
				<?php endif; ?>
			</div>
		</section>

		<?php AdminExtensionRegistry::render( 'overview' ); ?>
		<section class="cf-section" aria-labelledby="cf-coverage-title"><div class="cf-section__heading"><h3 id="cf-coverage-title"><?php echo $observing ? esc_html__( 'What Checkout Firewall is observing', 'checkout-firewall' ) : esc_html__( 'What you are protected against', 'checkout-firewall' ); ?></h3><p><?php echo $observing ? esc_html__( 'Six checks are measured but not enforced', 'checkout-firewall' ) : esc_html__( 'Six checks, evaluated before payment', 'checkout-firewall' ); ?></p></div><?php $this->coverage_grid( $recovery_ready, $observing ); ?></section>

		<section class="cf-section" aria-labelledby="cf-recent-title"><div class="cf-section__heading"><h3 id="cf-recent-title"><?php esc_html_e( 'Recent decisions', 'checkout-firewall' ); ?></h3><p><?php /* translators: %d: activity retention in days. */ echo esc_html( sprintf( __( 'Last %d days · actual and observed interventions', 'checkout-firewall' ), RetentionPolicy::event_seconds() / DAY_IN_SECONDS ) ); ?></p></div>
			<?php $this->summary_tiles( $summary ); ?>
			<?php if ( array() === $recent ) : ?>
				<div class="cf-empty-state"><strong><?php esc_html_e( 'No intervention signals yet', 'checkout-firewall' ); ?></strong><p><?php echo $observing ? esc_html__( 'Observe Mode is evaluating checkout locally. This list fills when it calculates that Standard Mode would challenge or stop an attempt.', 'checkout-firewall' ) : esc_html__( 'Protection is evaluating every checkout. This list stays empty until an attempt is challenged or blocked; ordinary successful checkouts are never recorded here.', 'checkout-firewall' ); ?></p></div>
			<?php else : ?>
				<?php $this->event_table( $recent ); ?><p><a class="cf-text-link" href="<?php echo esc_url( $this->view_url( 'activity' ) ); ?>"><?php esc_html_e( 'See all activity →', 'checkout-firewall' ); ?></a></p>
			<?php endif; ?>
		</section>

		<section class="cf-section" aria-labelledby="cf-health-title"><div class="cf-section__heading"><h3 id="cf-health-title"><?php esc_html_e( 'Protection health', 'checkout-firewall' ); ?></h3></div><div class="cf-panel"><?php $this->health_rows(); ?><?php $this->form_open( 'checkout_firewall_run_health' ); ?><button class="cf-button cf-button--primary" type="submit"><?php esc_html_e( 'Run health check', 'checkout-firewall' ); ?></button></form></div></section>

		<section class="cf-how-it-works" aria-labelledby="cf-how-title"><div><h3 id="cf-how-title"><?php esc_html_e( 'How Checkout Firewall protects your checkout', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Most customers are allowed silently. Uncertain traffic can recover with the selected browser check, while clear abuse is stopped before the gateway is asked to process payment.', 'checkout-firewall' ); ?></p></div><ol aria-label="<?php esc_attr_e( 'Checkout protection sequence', 'checkout-firewall' ); ?>"><li><?php esc_html_e( 'Checkout request', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Flow & honeypot signals', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Velocity & blocks', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Browser check if needed', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Decision', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Payment gateway', 'checkout-firewall' ); ?></li></ol><p class="cf-help"><?php esc_html_e( 'Checkout Firewall reduces checkout-abuse risk. It does not read card data and cannot prevent every fraudulent transaction or chargeback.', 'checkout-firewall' ); ?></p></section>
		<?php
	}

	private function activity(): void {
		$before_time = $this->get_date( 'before_time' );
		$before_id   = $this->get_id( 'before_id' );
		try {
			$rows = ( new EventRepository() )->page( $before_time, $before_id );
		} catch ( \Throwable $exception ) {
			$rows = array(); }
		$more = count( $rows ) > 50;
		$rows = array_slice( $rows, 0, 50 );
		?>
		<header class="cf-page-intro"><h2 id="cf-activity-title"><?php esc_html_e( 'Activity', 'checkout-firewall' ); ?></h2><p><?php /* translators: %d: activity retention in days. */ echo esc_html( sprintf( __( 'Checkout attempts that were challenged or stopped, plus what Observe Mode calculated it would have done. Kept for %d days and then removed automatically. Ordinary successful checkouts are not recorded.', 'checkout-firewall' ), RetentionPolicy::event_seconds() / DAY_IN_SECONDS ) ); ?></p></header>
		<?php AdminExtensionRegistry::render( 'activity' ); ?>
		<section class="cf-section" aria-labelledby="cf-activity-title">
		<?php $this->summary_tiles( $this->event_summary() ); ?>
		<?php
		if ( array() === $rows ) :
			?>
				<div class="cf-empty-state"><strong><?php esc_html_e( 'No interventions in the retained activity window', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Nothing has needed a challenge or block. Protection is still evaluating every checkout; this page fills only when an attempt is stopped.', 'checkout-firewall' ); ?></p></div>
				<?php
	else :
		?>
				<?php $this->event_table( $rows ); ?>
				<p class="cf-help"><?php esc_html_e( 'Repeated interventions are aggregated into hourly rows rather than stored request by request. Identity hints are masked; the raw IP address or email is not retained.', 'checkout-firewall' ); ?></p><?php endif; ?>
		<?php
		if ( $more ) :
			$last = end( $rows );
			?>
	<a class="button cf-button" href="
			<?php
			echo esc_url(
				add_query_arg(
					array(
						'page'        => self::SLUG,
						'view'        => 'activity',
						'before_time' => $last['last_seen_gmt'],
						'before_id'   => $last['id'],
					),
					admin_url( 'admin.php' )
				)
			);
			?>
"><?php esc_html_e( 'Load older', 'checkout-firewall' ); ?></a><?php endif; ?></section>
		<?php
	}

	private function blocks(): void {
		$after_time = $this->get_date( 'after_expiry' );
		$after_id   = $this->get_id( 'after_id' );
		try {
			$rows = ( new BlockRepository() )->page( $after_time, $after_id );
		} catch ( \Throwable $exception ) {
			$rows = array(); }
		$more = count( $rows ) > 50;
		$rows = array_slice( $rows, 0, 50 );
		try {
			$history = ( new BlockRepository() )->history();
		} catch ( \Throwable $exception ) {
			$history = array();
		}
		$exemptions = $this->exemptions->active();
		?>
		<header class="cf-page-intro"><h2><?php esc_html_e( 'Blocks', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'Identities that cannot currently complete checkout. Automatic blocks expire on their own. Release a block if a legitimate customer was caught.', 'checkout-firewall' ); ?></p></header>
		<section class="cf-section" aria-labelledby="cf-current-blocks"><div class="cf-section__heading"><h3 id="cf-current-blocks"><?php esc_html_e( 'Active blocks', 'checkout-firewall' ); ?></h3><p><?php /* translators: %d: number of visible active block rows. */ printf( esc_html( _n( '%d block shown', '%d blocks shown', count( $rows ), 'checkout-firewall' ) ), count( $rows ) ); ?></p></div>
		<?php
		if ( array() === $rows ) :
			?>
				<div class="cf-empty-state"><strong><?php esc_html_e( 'Nothing is blocked right now', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'No identity is currently prevented from checking out. Automatic and manual blocks appear here while they are in force.', 'checkout-firewall' ); ?></p></div>
				<?php
	else :
		?>
				<div class="cf-table-wrap"><table class="cf-table"><thead><tr><th scope="col"><?php esc_html_e( 'Identity', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Source', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Reason', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Blocked', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Expires', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Action', 'checkout-firewall' ); ?></th></tr></thead><tbody>
				<?php
				foreach ( $rows as $row ) :
					?>
		<tr><td data-label="<?php esc_attr_e( 'Identity', 'checkout-firewall' ); ?>"><strong><?php echo esc_html( $this->hint( $row ) ); ?></strong></td><td data-label="<?php esc_attr_e( 'Source', 'checkout-firewall' ); ?>"><span class="cf-pill cf-pill--neutral"><?php echo 'manual' === $row['source'] ? esc_html__( 'MANUAL', 'checkout-firewall' ) : esc_html__( 'AUTOMATIC', 'checkout-firewall' ); ?></span></td><td data-label="<?php esc_attr_e( 'Reason', 'checkout-firewall' ); ?>"><?php echo esc_html( $this->explanation( (string) $row['reason_code'] ) ); ?><small><code><?php echo esc_html( (string) $row['reason_code'] ); ?></code></small></td><td data-label="<?php esc_attr_e( 'Blocked', 'checkout-firewall' ); ?>"><?php echo esc_html( $this->date( (string) $row['created_at_gmt'] ) ); ?></td><td data-label="<?php esc_attr_e( 'Expires', 'checkout-firewall' ); ?>"><?php echo '9999-12-31 23:59:59' === $row['expires_at_gmt'] ? esc_html__( 'Until released', 'checkout-firewall' ) : esc_html( $this->date( (string) $row['expires_at_gmt'] ) ); ?></td><td data-label="<?php esc_attr_e( 'Action', 'checkout-firewall' ); ?>"><?php $this->form_open( 'checkout_firewall_release_block', (int) $row['id'] ); ?><input type="hidden" name="block_id" value="<?php echo esc_attr( (string) $row['id'] ); ?>" /><button class="cf-button cf-button--secondary cf-button--small" type="submit"><?php esc_html_e( 'Release', 'checkout-firewall' ); ?></button></form></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?>
		<?php
		if ( $more ) :
			$last = end( $rows );
			?>
	<a class="button cf-button" href="
			<?php
			echo esc_url(
				add_query_arg(
					array(
						'page'         => self::SLUG,
						'view'         => 'blocks',
						'after_expiry' => $last['expires_at_gmt'],
						'after_id'     => $last['id'],
					),
					admin_url( 'admin.php' )
				)
			);
			?>
"><?php esc_html_e( 'Load later expiries', 'checkout-firewall' ); ?></a><?php endif; ?></section>

		<section class="cf-panel cf-panel--spaced" aria-labelledby="cf-add-block"><div class="cf-panel__heading"><div><h3 id="cf-add-block"><?php esc_html_e( 'Block an identity manually', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Use this when you have identified abusive traffic yourself. The full value is hashed immediately and is not stored.', 'checkout-firewall' ); ?></p></div></div><?php $this->form_open( 'checkout_firewall_create_block' ); ?><div class="cf-form-grid"><div><label for="cf-block-type"><?php esc_html_e( 'Identity type', 'checkout-firewall' ); ?></label><select id="cf-block-type" name="identifier_type"><option value="ip"><?php esc_html_e( 'IP address', 'checkout-firewall' ); ?></option><option value="email"><?php esc_html_e( 'Email address', 'checkout-firewall' ); ?></option></select></div><div><label for="cf-block-value"><?php esc_html_e( 'Value', 'checkout-firewall' ); ?></label><input id="cf-block-value" type="text" name="identifier" maxlength="254" required autocomplete="off" placeholder="198.51.100.24" /></div><div><label for="cf-block-duration"><?php esc_html_e( 'Duration', 'checkout-firewall' ); ?></label><select id="cf-block-duration" name="block_duration"><option value="3600"><?php esc_html_e( '1 hour', 'checkout-firewall' ); ?></option><option value="86400"><?php esc_html_e( '24 hours', 'checkout-firewall' ); ?></option><option value="604800"><?php esc_html_e( '7 days', 'checkout-firewall' ); ?></option><option value="never"><?php esc_html_e( 'Until released', 'checkout-firewall' ); ?></option></select></div></div><button class="cf-button cf-button--primary" type="submit"><?php esc_html_e( 'Add block', 'checkout-firewall' ); ?></button></form></section>

		<section class="cf-panel cf-panel--spaced" aria-labelledby="cf-trusted-exemptions"><div class="cf-panel__heading"><div><h3 id="cf-trusted-exemptions"><?php esc_html_e( 'Trusted exemptions', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Exempt a known office network or signed-in customer from automatic velocity and payment-failure lockouts. Manual blocks and invalid or replayed checkout proof still win.', 'checkout-firewall' ); ?></p></div></div>
		<?php
		if ( array() !== $exemptions ) :
			?>
			<div class="cf-table-wrap"><table class="cf-table"><thead><tr><th><?php esc_html_e( 'Subject', 'checkout-firewall' ); ?></th><th><?php esc_html_e( 'Reason', 'checkout-firewall' ); ?></th><th><?php esc_html_e( 'Expires', 'checkout-firewall' ); ?></th><th><?php esc_html_e( 'Action', 'checkout-firewall' ); ?></th></tr></thead><tbody>
			<?php
			foreach ( $exemptions as $exemption ) :
				?>
	<tr><td><?php echo esc_html( $this->exemption_label( $exemption ) ); ?></td><td><?php echo esc_html( $this->exemption_reason( (string) $exemption['reason'] ) ); ?></td><td><?php echo '9999-12-31 23:59:59' === $exemption['expires_at_gmt'] ? esc_html__( 'Until removed', 'checkout-firewall' ) : esc_html( $this->date( (string) $exemption['expires_at_gmt'] ) ); ?></td><td><form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="checkout_firewall_remove_exemption" /><input type="hidden" name="exemption_id" value="<?php echo esc_attr( (string) $exemption['id'] ); ?>" /><?php wp_nonce_field( AdminActionController::exemption_nonce_action( (string) $exemption['id'] ) ); ?><button class="cf-button cf-button--secondary cf-button--small" type="submit"><?php esc_html_e( 'Remove', 'checkout-firewall' ); ?></button></form></td></tr><?php endforeach; ?></tbody></table></div>
			<?php
else :
	?>
			<div class="cf-empty-state cf-empty-state--compact"><p><?php esc_html_e( 'No trusted exemptions are active.', 'checkout-firewall' ); ?></p></div><?php endif; ?>
		<?php $this->form_open( 'checkout_firewall_create_exemption' ); ?><div class="cf-form-grid"><div><label for="cf-exemption-type"><?php esc_html_e( 'Subject type', 'checkout-firewall' ); ?></label><select id="cf-exemption-type" name="exemption_type"><option value="ip"><?php esc_html_e( 'IP address or narrow CIDR', 'checkout-firewall' ); ?></option><option value="user"><?php esc_html_e( 'Authenticated WordPress user ID', 'checkout-firewall' ); ?></option></select></div><div><label for="cf-exemption-value"><?php esc_html_e( 'Value', 'checkout-firewall' ); ?></label><input id="cf-exemption-value" name="exemption_value" maxlength="254" required autocomplete="off" placeholder="198.51.100.24" /></div><div><label for="cf-exemption-reason"><?php esc_html_e( 'Reason', 'checkout-firewall' ); ?></label><select id="cf-exemption-reason" name="exemption_reason"><option value="office_network"><?php esc_html_e( 'Office network', 'checkout-firewall' ); ?></option><option value="wholesale_customer"><?php esc_html_e( 'Wholesale customer', 'checkout-firewall' ); ?></option><option value="vip_customer"><?php esc_html_e( 'VIP customer', 'checkout-firewall' ); ?></option><option value="testing"><?php esc_html_e( 'Authorized testing', 'checkout-firewall' ); ?></option></select></div><div><label for="cf-exemption-duration"><?php esc_html_e( 'Duration', 'checkout-firewall' ); ?></label><select id="cf-exemption-duration" name="exemption_duration"><option value="86400"><?php esc_html_e( '1 day', 'checkout-firewall' ); ?></option><option value="604800"><?php esc_html_e( '7 days', 'checkout-firewall' ); ?></option><option value="2592000"><?php esc_html_e( '30 days', 'checkout-firewall' ); ?></option><option value="never"><?php esc_html_e( 'Until removed', 'checkout-firewall' ); ?></option></select></div></div><button class="cf-button cf-button--primary" type="submit"><?php esc_html_e( 'Add trusted exemption', 'checkout-firewall' ); ?></button><p class="cf-help"><?php esc_html_e( 'Email cannot be trusted because a guest can type any billing address. Exact IPs are keyed immediately. CIDRs are stored as entered for range matching and are limited to /24 or narrower for IPv4 and /64 or narrower for IPv6.', 'checkout-firewall' ); ?></p></form></section>

		<section class="cf-section" aria-labelledby="cf-block-history"><div class="cf-section__heading"><h3 id="cf-block-history"><?php esc_html_e( 'Recently released and expired', 'checkout-firewall' ); ?></h3><p><?php /* translators: %d: terminal block retention in days. */ echo esc_html( sprintf( __( 'Kept for %d days after a block ends', 'checkout-firewall' ), RetentionPolicy::history_seconds() / DAY_IN_SECONDS ) ); ?></p></div>
		<?php
		if ( array() === $history ) :
			?>
			<div class="cf-empty-state cf-empty-state--compact"><p><?php esc_html_e( 'No recently released or expired blocks.', 'checkout-firewall' ); ?></p></div>
			<?php
else :
	?>
			<ul class="cf-history-list">
			<?php
			foreach ( $history as $row ) :
				?>
		<li><strong><?php echo esc_html( $this->hint( $row ) ); ?></strong><span><?php echo esc_html( $this->explanation( (string) $row['reason_code'] ) ); ?></span><time><?php /* translators: %s: localized date and time. */ echo esc_html( 'released' === $row['status'] ? sprintf( __( 'Released %s', 'checkout-firewall' ), $this->date( (string) $row['released_at_gmt'] ) ) : sprintf( __( 'Expired %s', 'checkout-firewall' ), $this->date( (string) $row['expires_at_gmt'] ) ) ); ?></time></li><?php endforeach; ?></ul><?php endif; ?></section>
		<?php
	}

	private function settings(): void {
		$resolver     = new ClientIpResolver();
		$proxy        = $resolver->configured_mode();
		$edge         = $resolver->edge_status();
		$cidrs        = get_option( ClientIpResolver::CIDRS_OPTION, array() );
		$proxy_labels = array(
			'automatic'                  => __( 'AUTOMATIC', 'checkout-firewall' ),
			'automatic:cloudflare'       => __( 'AUTOMATIC · CLOUDFLARE DETECTED', 'checkout-firewall' ),
			'automatic:cloudflare_error' => __( 'AUTOMATIC · CHECK CLOUDFLARE', 'checkout-firewall' ),
			'manual'                     => __( 'CUSTOM PROXY', 'checkout-firewall' ),
		);
		$proxy_key    = ClientIpResolver::MODE_AUTOMATIC === $proxy && 'cloudflare' === $edge ? 'automatic:cloudflare' : ( ClientIpResolver::MODE_AUTOMATIC === $proxy && 'cloudflare_header_missing' === $edge ? 'automatic:cloudflare_error' : $proxy );
		$proxy_label  = $proxy_labels[ $proxy_key ] ?? __( 'REVIEW NEEDED', 'checkout-firewall' );
		?>
		<header class="cf-page-intro"><h2><?php esc_html_e( 'Settings', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'Protection works immediately with a private local browser check. Turnstile and Google reCAPTCHA are optional alternatives.', 'checkout-firewall' ); ?></p></header>
		<?php AdminExtensionRegistry::render( 'settings' ); ?>
		<?php $this->challenge_provider_settings(); ?>
		<?php $this->challenge_provider_details(); ?>
		<?php $this->form_open( 'checkout_firewall_save_operations' ); ?>
		<section class="cf-panel cf-panel--spaced" aria-labelledby="cf-retention-settings"><div class="cf-panel__heading"><div><h3 id="cf-retention-settings"><?php esc_html_e( 'How long to keep records', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Shorter is more private; longer helps investigate an incident. Records are removed automatically at the end of the selected window.', 'checkout-firewall' ); ?></p></div></div><div class="cf-setting-list">
			<div><label for="cf-event-retention"><strong><?php esc_html_e( 'Activity', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'Challenges and blocks shown on the Activity page, plus temporary payment-feedback snapshots on pending orders', 'checkout-firewall' ); ?></span></label><?php $this->select_days( 'event_retention', 'cf-event-retention', array( 1, 3, 7 ), (int) get_option( RetentionPolicy::EVENT_OPTION, 7 ) ); ?></div>
			<div><label for="cf-history-retention"><strong><?php esc_html_e( 'Released and expired blocks', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'History of blocks that are no longer in force', 'checkout-firewall' ); ?></span></label><?php $this->select_days( 'history_retention', 'cf-history-retention', array( 1, 3, 7 ), (int) get_option( RetentionPolicy::HISTORY_OPTION, 7 ) ); ?></div>
			<div><label for="cf-hint-retention"><strong><?php esc_html_e( 'Masked identity hints', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'Partial values that help recognize repeat abusive traffic', 'checkout-firewall' ); ?></span></label><?php $this->select_days( 'hint_retention', 'cf-hint-retention', array( 7, 30, 90 ), (int) get_option( RetentionPolicy::HINT_OPTION, 90 ) ); ?></div>
		</div></section>
		<section class="cf-panel cf-panel--spaced" aria-labelledby="cf-notification-settings"><div class="cf-panel__heading"><div><h3 id="cf-notification-settings"><?php esc_html_e( 'Security notifications', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Send one privacy-safe message when Emergency Mode starts or sustained checkout-abuse signals open a local incident. Delivery is handled by WordPress mail and is not guaranteed.', 'checkout-firewall' ); ?></p></div></div><label class="cf-check"><input type="checkbox" name="email_enabled" value="1" <?php checked( ( new AttackStartMailer() )->enabled() ); ?> /> <?php esc_html_e( 'Email me about Emergency Mode and elevated checkout activity', 'checkout-firewall' ); ?></label><label for="cf-email"><?php esc_html_e( 'Recipient', 'checkout-firewall' ); ?></label><input id="cf-email" type="email" name="email_recipient" maxlength="254" value="<?php echo esc_attr( ( new AttackStartMailer() )->recipient() ); ?>" required /></section>
		<details class="cf-panel cf-panel--spaced cf-advanced-details">
			<summary><span class="cf-advanced-details__title"><span class="cf-eyebrow"><?php esc_html_e( 'ADVANCED NETWORK SETTING', 'checkout-firewall' ); ?></span><strong id="cf-proxy-settings"><?php esc_html_e( 'Visitor IP detection', 'checkout-firewall' ); ?></strong><small><?php esc_html_e( 'Direct and Cloudflare traffic are detected automatically.', 'checkout-firewall' ); ?></small></span><span class="cf-advanced-details__meta"><span class="cf-pill cf-pill--neutral"><?php echo esc_html( $proxy_label ); ?></span><span aria-hidden="true">+</span></span></summary>
			<div class="cf-advanced-details__body" aria-labelledby="cf-proxy-settings">
				<div class="cf-explainer-grid"><div><strong><?php esc_html_e( 'What does this do?', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Checkout Firewall uses a privacy-protected version of a visitor’s IP address as one of several signals for spotting unusually fast repeated checkout attempts. It automatically uses the direct connection address or Cloudflare’s visitor address when Cloudflare is verified.', 'checkout-firewall' ); ?></p></div><div><strong><?php esc_html_e( 'When should I change it?', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Only when your host confirms that another reverse proxy or CDN sits in front of WordPress. Ask the host for the exact visitor-address header and trusted IP ranges.', 'checkout-firewall' ); ?></p></div><div><strong><?php esc_html_e( 'Why does it matter?', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'A wrong custom setting can make many customers look like one visitor or can trust an address supplied by an attacker. Do not guess proxy addresses or headers.', 'checkout-firewall' ); ?></p></div></div>
				<div class="cf-form-grid cf-form-grid--two"><div><label for="cf-proxy-mode"><?php esc_html_e( 'How traffic reaches WordPress', 'checkout-firewall' ); ?></label><select id="cf-proxy-mode" name="proxy_mode"><option value="automatic" <?php selected( $proxy, ClientIpResolver::MODE_AUTOMATIC ); ?>><?php esc_html_e( 'Automatic — Direct or verified Cloudflare', 'checkout-firewall' ); ?></option><option value="manual" <?php selected( $proxy, ClientIpResolver::MODE_MANUAL ); ?>><?php esc_html_e( 'Another trusted proxy — host supplied', 'checkout-firewall' ); ?></option></select></div><div><label for="cf-proxy-header"><?php esc_html_e( 'Visitor-address header — custom proxy only', 'checkout-firewall' ); ?></label><select id="cf-proxy-header" name="proxy_header"><option value="HTTP_X_FORWARDED_FOR" <?php selected( get_option( ClientIpResolver::HEADER_OPTION, 'HTTP_X_FORWARDED_FOR' ), 'HTTP_X_FORWARDED_FOR' ); ?>>X-Forwarded-For</option><option value="HTTP_X_REAL_IP" <?php selected( get_option( ClientIpResolver::HEADER_OPTION, '' ), 'HTTP_X_REAL_IP' ); ?>>X-Real-IP</option></select></div></div>
				<label for="cf-proxy-cidrs"><?php esc_html_e( 'Trusted proxy IP ranges — custom proxy only, one CIDR per line', 'checkout-firewall' ); ?></label><textarea id="cf-proxy-cidrs" name="proxy_cidrs" maxlength="4096" rows="5" placeholder="192.0.2.0/24"><?php echo esc_textarea( is_array( $cidrs ) ? implode( "\n", $cidrs ) : '' ); ?></textarea><p class="cf-help"><?php esc_html_e( 'Cloudflare is detected automatically from its verified network ranges; no Cloudflare setup is needed here. For another proxy, copy the exact header and CIDR ranges supplied by your hosting provider.', 'checkout-firewall' ); ?></p>
			</div>
		</details>
		<p class="cf-form-submit"><button class="cf-button cf-button--primary" type="submit"><?php esc_html_e( 'Save operations settings', 'checkout-firewall' ); ?></button></p></form>
		<?php $this->key_settings(); ?>
		<?php
	}

	private function privacy(): void {
		$uninstall_locked = defined( 'CHECKOUT_FIREWALL_DELETE_DATA_ON_UNINSTALL' ) && true === CHECKOUT_FIREWALL_DELETE_DATA_ON_UNINSTALL;
		?>
		<header class="cf-page-intro"><h2><?php esc_html_e( 'Privacy & help', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'Exactly what Checkout Firewall retains locally, what can leave your server, and how to get safe diagnostic help.', 'checkout-firewall' ); ?></p></header>
		<section class="cf-panel" aria-labelledby="cf-privacy-title">
			<div class="cf-panel__heading"><h3 id="cf-privacy-title"><?php esc_html_e( 'What stays on your server', 'checkout-firewall' ); ?></h3></div>
			<ul class="cf-disclosure-list cf-disclosure-list--included"><li><?php esc_html_e( 'Actual intervention records and Observe Mode records of what Standard Mode would have challenged or blocked, including a reason code and bounded count.', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Keyed one-way identifiers for IP, email, session, and IP plus email, with an approved masked hint.', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'A temporary keyed payment-feedback snapshot on a pending order. It is deleted after a recorded success or failure and otherwise expires within the Activity retention window.', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Active and recently ended blocks, protection settings, identity-free incident counts, and local health state.', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Trusted exemptions for a local user ID, a keyed exact IP, or a narrow raw network range needed for CIDR matching.', 'checkout-firewall' ); ?></li></ul>
			<h3><?php esc_html_e( 'What Checkout Firewall never stores', 'checkout-firewall' ); ?></h3><ul class="cf-disclosure-list cf-disclosure-list--excluded"><li><?php esc_html_e( 'Card numbers, security codes, gateway payment payloads, or request bodies.', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'A Checkout Firewall activity record for ordinary successful checkouts.', 'checkout-firewall' ); ?></li><li><?php esc_html_e( 'Raw exact IP addresses or email addresses after the immediate local decision is derived. A narrow CIDR is stored only when an administrator explicitly creates that trusted network exemption.', 'checkout-firewall' ); ?></li></ul>
			<p><?php esc_html_e( 'Use WordPress → Tools → Erase Personal Data for confirmed email erasure. An email alone cannot attribute IP, session, or combined aggregates.', 'checkout-firewall' ); ?></p>
		</section>
		<?php AdminExtensionRegistry::render( 'privacy' ); ?>
		<section class="cf-panel cf-panel--spaced" aria-labelledby="cf-licensing-title">
			<div class="cf-panel__heading"><div><h3 id="cf-licensing-title"><?php esc_html_e( 'What can leave your server', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'External services remain optional and are never used for checkout telemetry.', 'checkout-firewall' ); ?></p></div></div>
			<div class="cf-service-box"><strong><?php esc_html_e( 'Private local browser check', 'checkout-firewall' ); ?></strong><span class="cf-pill <?php echo ChallengeConfig::LOCAL === $this->challenges->effective() ? 'cf-pill--allow' : 'cf-pill--neutral'; ?>"><?php echo ChallengeConfig::LOCAL === $this->challenges->effective() ? esc_html__( 'IN USE', 'checkout-firewall' ) : esc_html__( 'AVAILABLE', 'checkout-firewall' ); ?></span><p><?php esc_html_e( 'The default proof-of-work check runs in the shopper browser and is verified by this store. It does not contact an outside challenge provider.', 'checkout-firewall' ); ?></p></div>
			<div class="cf-service-box"><strong><?php esc_html_e( 'Cloudflare Turnstile', 'checkout-firewall' ); ?></strong><span class="cf-pill <?php echo ChallengeConfig::TURNSTILE === $this->challenges->effective() ? 'cf-pill--allow' : 'cf-pill--neutral'; ?>"><?php echo ChallengeConfig::TURNSTILE === $this->challenges->effective() ? esc_html__( 'IN USE', 'checkout-firewall' ) : esc_html__( 'NOT IN USE', 'checkout-firewall' ); ?></span><p><?php esc_html_e( 'When selected and a challenge is shown, the shopper browser contacts Cloudflare and this server verifies the result. Checkout Firewall omits the optional shopper IP from server-side verification.', 'checkout-firewall' ); ?></p></div>
			<div class="cf-service-box"><strong><?php esc_html_e( 'Google reCAPTCHA', 'checkout-firewall' ); ?></strong><span class="cf-pill <?php echo ChallengeConfig::RECAPTCHA === $this->challenges->effective() ? 'cf-pill--allow' : 'cf-pill--neutral'; ?>"><?php echo ChallengeConfig::RECAPTCHA === $this->challenges->effective() ? esc_html__( 'IN USE', 'checkout-firewall' ) : esc_html__( 'NOT IN USE', 'checkout-firewall' ); ?></span><p><?php esc_html_e( 'When selected and a challenge is shown, the shopper browser contacts Google and this server verifies the result. Checkout Firewall sends no payment details to Google.', 'checkout-firewall' ); ?></p></div>
			<div class="cf-service-box"><strong><?php esc_html_e( 'Codeprint account via Freemius', 'checkout-firewall' ); ?></strong><span class="cf-pill cf-pill--neutral"><?php esc_html_e( 'OPTIONAL', 'checkout-firewall' ); ?></span>
			<p><?php esc_html_e( 'Free protection works locally without an account, and Free updates come from WordPress.org. Connecting an optional Freemius account first shows its consent screen and supports account, purchase, and separately installed Premium licensing and updates.', 'checkout-firewall' ); ?></p>
			<p class="cf-help"><?php esc_html_e( 'Checkout Firewall does not request marketing email, diagnostic tracking, or installed plugin and theme inventory.', 'checkout-firewall' ); ?></p>
			<p class="cf-help"><?php esc_html_e( 'Checkout decisions, blocks, identifiers, orders, gateway data, Turnstile data, Emergency Mode state, and security events are never sent to Codeprint or Freemius. The same boundary covers local and reCAPTCHA challenge responses.', 'checkout-firewall' ); ?></p>
			<?php if ( CommercialBootstrap::config()->is_configured() ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="<?php echo esc_attr( CommercialAccountController::ACTION ); ?>" />
					<?php wp_nonce_field( CommercialAccountController::ACTION ); ?>
					<button class="button cf-button" type="submit"><?php esc_html_e( 'Connect optional Freemius account', 'checkout-firewall' ); ?></button>
				</form>
			<?php else : ?>
				<p class="cf-help"><?php esc_html_e( 'Connection is unavailable until an approved product configuration is installed. Free protection is unaffected.', 'checkout-firewall' ); ?></p>
			<?php endif; ?>
			</div>
		</section>
		<div class="cf-help-grid">
		<section class="cf-panel" aria-labelledby="cf-support-title">
			<div class="cf-panel__heading"><h3 id="cf-support-title"><?php esc_html_e( 'Support snapshot', 'checkout-firewall' ); ?></h3></div>
			<p><?php esc_html_e( 'Download a local diagnostic summary with software versions, closed health states, schedule presence, configuration states, and bucketed Checkout Firewall table sizes.', 'checkout-firewall' ); ?></p>
			<p class="cf-help"><?php esc_html_e( 'The snapshot excludes store and site identity, paths, administrators, customers, IP addresses, emails, orders, gateways, security identifiers, keys, tokens, request data, logs, and raw errors. It is generated locally and is not uploaded.', 'checkout-firewall' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( SupportExportController::ACTION ); ?>" />
				<?php wp_nonce_field( SupportExportController::ACTION ); ?>
				<button class="button cf-button" type="submit"><?php esc_html_e( 'Download support snapshot', 'checkout-firewall' ); ?></button>
			</form>
		</section>
		<section class="cf-panel" aria-labelledby="cf-personal-data-title"><div class="cf-panel__heading"><h3 id="cf-personal-data-title"><?php esc_html_e( 'Personal data tools', 'checkout-firewall' ); ?></h3></div><p><?php esc_html_e( 'WordPress can erase directly email-keyed Checkout Firewall rows after an administrator confirms the request.', 'checkout-firewall' ); ?></p>
		<?php
		if ( current_user_can( 'erase_others_personal_data' ) ) :
			?>
			<p><a class="cf-button cf-button--secondary" href="<?php echo esc_url( admin_url( 'erase-personal-data.php' ) ); ?>"><?php esc_html_e( 'Open Erase Personal Data', 'checkout-firewall' ); ?></a></p><?php endif; ?></section>
		</div>
		<section class="cf-panel cf-panel--spaced" aria-labelledby="cf-uninstall-title">
			<div class="cf-panel__heading"><div><h3 id="cf-uninstall-title"><?php esc_html_e( 'If you uninstall', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Data is preserved by default so reinstalling can restore your protection settings and history.', 'checkout-firewall' ); ?></p></div></div>
			<?php $this->form_open( 'checkout_firewall_save_uninstall' ); ?>
			<label><input type="radio" name="uninstall_data" value="preserve" <?php checked( ! \Codeprint\CheckoutFirewall\Lifecycle\Uninstaller::purge_is_authorized() ); ?> <?php disabled( $uninstall_locked ); ?> /> <?php esc_html_e( 'Preserve data', 'checkout-firewall' ); ?></label>
			<label><input type="radio" name="uninstall_data" value="delete" <?php checked( \Codeprint\CheckoutFirewall\Lifecycle\Uninstaller::purge_is_authorized() ); ?> <?php disabled( $uninstall_locked ); ?> /> <?php esc_html_e( 'Delete all Checkout Firewall data on uninstall', 'checkout-firewall' ); ?></label>
			<label for="cf-delete-confirm"><?php esc_html_e( 'Type DELETE when enabling deletion', 'checkout-firewall' ); ?></label><input id="cf-delete-confirm" type="text" name="confirmation" maxlength="16" autocomplete="off" <?php disabled( $uninstall_locked ); ?> />
			<p class="cf-help"><?php echo $uninstall_locked ? esc_html__( 'CHECKOUT_FIREWALL_DELETE_DATA_ON_UNINSTALL is enabled in wp-config.php. This control is read-only.', 'checkout-firewall' ) : esc_html__( 'Saving this choice deletes nothing now. Full deletion is irreversible if the plugin is later uninstalled.', 'checkout-firewall' ); ?></p>
			<button class="button button-primary cf-button" type="submit" <?php disabled( $uninstall_locked ); ?>><?php esc_html_e( 'Save uninstall behavior', 'checkout-firewall' ); ?></button></form>
		</section>
		<?php
	}

	private function challenge_provider_settings(): void {
		$selected  = $this->challenges->selected();
		$effective = $this->challenges->effective();
		$labels    = array(
			ChallengeConfig::LOCAL     => __( 'Private local check', 'checkout-firewall' ),
			ChallengeConfig::TURNSTILE => __( 'Cloudflare Turnstile', 'checkout-firewall' ),
			ChallengeConfig::RECAPTCHA => __( 'Google reCAPTCHA', 'checkout-firewall' ),
			ChallengeConfig::NONE      => __( 'No browser challenge', 'checkout-firewall' ),
		);
		?>
		<section class="cf-panel cf-panel--spaced" aria-labelledby="cf-challenge-provider-title">
			<div class="cf-panel__heading"><div><p class="cf-eyebrow"><?php esc_html_e( 'CHECKOUT RECOVERY', 'checkout-firewall' ); ?></p><h3 id="cf-challenge-provider-title"><?php esc_html_e( 'Browser challenge provider', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Choose the browser check Checkout Firewall uses when checkout needs verification.', 'checkout-firewall' ); ?></p></div><span class="cf-pill <?php echo ChallengeConfig::NONE === $effective ? 'cf-pill--challenge' : 'cf-pill--allow'; ?>"><?php echo esc_html( $labels[ $effective ] ?? __( 'Unavailable', 'checkout-firewall' ) ); ?></span></div>
			<div class="cf-notice"><strong><?php esc_html_e( 'Automatic bot signals are active', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Checkout Firewall combines velocity, a randomized honeypot, signed timing evidence, and bounded browser-request signals. Strong evidence or multiple supporting signals can request verification; they never create a permanent block.', 'checkout-firewall' ); ?></p></div>
			<?php
			if ( $this->challenges->is_fallback() ) :
				?>
				<div class="cf-notice cf-notice--challenge"><strong><?php esc_html_e( 'Using the private local fallback', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'The selected external provider is not verified, so recoverable checkouts use the local browser check until setup is complete.', 'checkout-firewall' ); ?></p></div><?php endif; ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-cf-provider-selector data-saved-provider="<?php echo esc_attr( $selected ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( ChallengeSettingsController::SELECT_ACTION ); ?>" /><?php wp_nonce_field( ChallengeSettingsController::NONCE_ACTION ); ?>
				<div class="cf-provider-grid">
					<label><input type="radio" name="challenge_provider" value="local" aria-controls="cf-provider-local-panel" <?php checked( ChallengeConfig::LOCAL, $selected ); ?> /><strong><?php esc_html_e( 'Private local check', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'Ready immediately. A short proof-of-work check runs in the shopper browser and is verified only by your store.', 'checkout-firewall' ); ?></span></label>
					<label><input type="radio" name="challenge_provider" value="turnstile" aria-controls="cf-provider-turnstile-panel" <?php checked( ChallengeConfig::TURNSTILE, $selected ); ?> /><strong><?php esc_html_e( 'Cloudflare Turnstile · Recommended', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'Best fit for most stores. Requires free Cloudflare Turnstile keys and contacts Cloudflare only when checkout requires verification.', 'checkout-firewall' ); ?></span></label>
					<label><input type="radio" name="challenge_provider" value="recaptcha" aria-controls="cf-provider-recaptcha-panel" <?php checked( ChallengeConfig::RECAPTCHA, $selected ); ?> /><strong><?php esc_html_e( 'Google reCAPTCHA', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'Optional reCAPTCHA v2 checkbox support. Requires Google site and secret keys.', 'checkout-firewall' ); ?></span></label>
					<label><input type="radio" name="challenge_provider" value="none" aria-controls="cf-provider-none-panel" <?php checked( ChallengeConfig::NONE, $selected ); ?> /><strong><?php esc_html_e( 'No browser challenge · Advanced', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'When a recoverable limit is reached, checkout is temporarily throttled instead of showing a challenge.', 'checkout-firewall' ); ?></span></label>
				</div><button class="button button-primary cf-button" type="submit" <?php disabled( $this->mode->is_active() ); ?>><?php esc_html_e( 'Save challenge provider', 'checkout-firewall' ); ?></button>
				<p class="cf-provider-pending" data-cf-provider-pending hidden><?php esc_html_e( 'The settings for your new choice are shown below. Save the provider choice when you are ready to use it.', 'checkout-firewall' ); ?></p>
			</form>
		</section>
		<section class="cf-panel cf-panel--spaced" aria-labelledby="cf-challenge-policy-title">
			<div class="cf-panel__heading"><div><p class="cf-eyebrow"><?php esc_html_e( 'WHEN SHOPPERS SEE IT', 'checkout-firewall' ); ?></p><h3 id="cf-challenge-policy-title"><?php esc_html_e( 'Challenge timing', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Adaptive protection keeps ordinary checkout friction-free. Always for guests shows the selected provider before every guest places an order.', 'checkout-firewall' ); ?></p></div></div>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( ChallengeSettingsController::POLICY_ACTION ); ?>" /><?php wp_nonce_field( ChallengeSettingsController::NONCE_ACTION ); ?>
				<div class="cf-provider-grid">
					<label><input type="radio" name="challenge_policy" value="adaptive" <?php checked( ChallengePolicy::ADAPTIVE, $this->challenge_policy->current() ); ?> /><strong><?php esc_html_e( 'Adaptive · Recommended', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'Show verification only when local checkout behavior, Emergency Mode, or eligible Premium attack state calls for it.', 'checkout-firewall' ); ?></span></label>
					<label><input type="radio" name="challenge_policy" value="always_guests" <?php checked( ChallengePolicy::ALWAYS_GUESTS, $this->challenge_policy->current() ); ?> /><strong><?php esc_html_e( 'Always for guest checkout', 'checkout-firewall' ); ?></strong><span><?php esc_html_e( 'Display the selected check before every guest order. Logged-in customers remain adaptive.', 'checkout-firewall' ); ?></span></label>
				</div>
				<p class="cf-help"><?php esc_html_e( 'Observe Mode never loads or verifies a remote checkout provider. If you select Always for guests, it begins only after Standard Mode is enabled.', 'checkout-firewall' ); ?></p>
				<button class="button button-primary cf-button" type="submit"><?php esc_html_e( 'Save challenge timing', 'checkout-firewall' ); ?></button>
			</form>
		</section>
		<?php
	}

	private function challenge_provider_details(): void {
		$selected = $this->challenges->selected();
		?>
		<div id="cf-provider-local-panel" class="cf-provider-detail" data-cf-provider-panel="local" aria-hidden="<?php echo ChallengeConfig::LOCAL === $selected ? 'false' : 'true'; ?>" <?php echo ChallengeConfig::LOCAL === $selected ? '' : 'hidden'; ?>>
			<section class="cf-panel" aria-labelledby="cf-local-provider-title"><div class="cf-panel__heading"><div><p class="cf-eyebrow"><?php esc_html_e( 'READY NOW · NO API KEYS', 'checkout-firewall' ); ?></p><h3 id="cf-local-provider-title"><?php esc_html_e( 'Private local browser check', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Nothing else is required. The challenge runs in the shopper browser and is verified by this store without contacting an outside challenge provider.', 'checkout-firewall' ); ?></p></div><span class="cf-pill cf-pill--allow"><?php esc_html_e( 'READY', 'checkout-firewall' ); ?></span></div><p class="cf-help"><?php esc_html_e( 'This is lightweight computational friction, not proof that the shopper is human. Turnstile remains the recommended stronger option for stores that want managed bot detection.', 'checkout-firewall' ); ?></p></section>
		</div>
		<div id="cf-provider-turnstile-panel" class="cf-provider-detail" data-cf-provider-panel="turnstile" aria-hidden="<?php echo ChallengeConfig::TURNSTILE === $selected ? 'false' : 'true'; ?>" <?php echo ChallengeConfig::TURNSTILE === $selected ? '' : 'hidden'; ?>><?php $this->turnstile_settings(); ?></div>
		<div id="cf-provider-recaptcha-panel" class="cf-provider-detail" data-cf-provider-panel="recaptcha" aria-hidden="<?php echo ChallengeConfig::RECAPTCHA === $selected ? 'false' : 'true'; ?>" <?php echo ChallengeConfig::RECAPTCHA === $selected ? '' : 'hidden'; ?>><?php $this->recaptcha_settings(); ?></div>
		<div id="cf-provider-none-panel" class="cf-provider-detail" data-cf-provider-panel="none" aria-hidden="<?php echo ChallengeConfig::NONE === $selected ? 'false' : 'true'; ?>" <?php echo ChallengeConfig::NONE === $selected ? '' : 'hidden'; ?>>
			<section class="cf-panel" aria-labelledby="cf-no-provider-title"><div class="cf-panel__heading"><div><p class="cf-eyebrow"><?php esc_html_e( 'ADVANCED · NO RECOVERY CHALLENGE', 'checkout-firewall' ); ?></p><h3 id="cf-no-provider-title"><?php esc_html_e( 'Temporary throttling only', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Recoverable limits do not show a browser challenge. Checkout is temporarily throttled instead, while explicit blocks and invalid checkout-flow proof remain enforced.', 'checkout-firewall' ); ?></p></div><span class="cf-pill cf-pill--challenge"><?php esc_html_e( 'REVIEW', 'checkout-firewall' ); ?></span></div><p class="cf-help"><?php esc_html_e( 'Use this only when your store cannot present any browser challenge. It gives legitimate shoppers fewer ways to recover from an uncertain-looking attempt.', 'checkout-firewall' ); ?></p></section>
		</div>
		<?php
	}

	private function recaptcha_settings(): void {
		$credentials = $this->recaptcha->credentials();
		$configured  = '' !== $credentials['site_key'] && '' !== $credentials['secret_key'];
		$active      = $this->recaptcha->is_active();
		?>
		<section class="cf-panel" aria-labelledby="cf-recaptcha-title">
			<div class="cf-panel__heading"><div><p class="cf-eyebrow"><?php esc_html_e( 'OPTIONAL PROVIDER · API KEYS', 'checkout-firewall' ); ?></p><h3 id="cf-recaptcha-title"><?php esc_html_e( 'Google reCAPTCHA', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'reCAPTCHA v2 checkbox; Google account and site and secret keys required.', 'checkout-firewall' ); ?></p></div><span class="cf-pill <?php echo $active ? 'cf-pill--allow' : ( $configured ? 'cf-pill--challenge' : 'cf-pill--neutral' ); ?>"><?php echo $active ? esc_html__( 'VERIFIED', 'checkout-firewall' ) : ( $configured ? esc_html__( 'KEYS SAVED · TEST REQUIRED', 'checkout-firewall' ) : esc_html__( 'SETUP REQUIRED', 'checkout-firewall' ) ); ?></span></div>
			<div aria-labelledby="cf-recaptcha-title">
				<p><?php esc_html_e( 'Choose this only if your store already uses Google reCAPTCHA or you prefer it to the private local check and Turnstile. The shopper browser contacts Google only when checkout requires verification under your saved challenge timing or an active protection state.', 'checkout-firewall' ); ?></p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="<?php echo esc_attr( ChallengeSettingsController::SAVE_ACTION ); ?>" /><?php wp_nonce_field( ChallengeSettingsController::NONCE_ACTION ); ?><label for="cf-recaptcha-site-key"><?php esc_html_e( 'Site key', 'checkout-firewall' ); ?></label><input id="cf-recaptcha-site-key" name="site_key" type="text" maxlength="128" value="<?php echo esc_attr( $credentials['site_key'] ); ?>" required <?php wp_readonly( defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SITE_KEY' ) ); ?> /><label for="cf-recaptcha-secret-key"><?php esc_html_e( 'Secret key', 'checkout-firewall' ); ?></label><input id="cf-recaptcha-secret-key" name="secret_key" type="password" maxlength="256" value="" autocomplete="new-password" placeholder="<?php echo '' === $credentials['secret_key'] ? esc_attr__( 'Required', 'checkout-firewall' ) : esc_attr__( 'Saved — leave blank to keep it', 'checkout-firewall' ); ?>" <?php wp_readonly( defined( 'CHECKOUT_FIREWALL_RECAPTCHA_SECRET_KEY' ) ); ?> /><p class="cf-help"><?php esc_html_e( 'Saving a change disables reCAPTCHA until this store verifies the new keys.', 'checkout-firewall' ); ?></p><div class="cf-actions"><button class="button button-primary cf-button" type="submit"><?php esc_html_e( 'Save reCAPTCHA keys', 'checkout-firewall' ); ?></button>
				<?php
				if ( '' !== $credentials['site_key'] ) :
					?>
					<button class="button cf-button" name="remove" value="1" type="submit"><?php esc_html_e( 'Remove keys', 'checkout-firewall' ); ?></button><?php endif; ?></div></form>
				<?php
				if ( $configured ) :
					?>
					<p class="cf-help"><?php esc_html_e( 'This connection test loads reCAPTCHA on this settings page and asks Google to validate the result. It does not run a checkout or payment.', 'checkout-firewall' ); ?></p><form class="cf-health cf-recaptcha-health" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-site-key="<?php echo esc_attr( $credentials['site_key'] ); ?>" data-load-error="<?php esc_attr_e( 'Google reCAPTCHA could not load. Check browser privacy controls and this site’s Content Security Policy, then retry.', 'checkout-firewall' ); ?>" data-widget-error="<?php esc_attr_e( 'Google reCAPTCHA could not complete the connection test. Reload this page and try again.', 'checkout-firewall' ); ?>"><input type="hidden" name="action" value="<?php echo esc_attr( ChallengeSettingsController::VERIFY_ACTION ); ?>" /><?php wp_nonce_field( ChallengeSettingsController::NONCE_ACTION ); ?><input type="hidden" name="health_token" value="" /><div class="cf-health__widget" aria-live="polite"></div><button class="button button-primary cf-button" type="button" data-cf-recaptcha-verify disabled><?php esc_html_e( 'Test connection and enable reCAPTCHA', 'checkout-firewall' ); ?></button></form>
				<?php else : ?>
					<div class="cf-notice cf-notice--challenge"><strong><?php esc_html_e( 'reCAPTCHA connection test unavailable', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Save both the site key and secret key first. Checkout Firewall will not enable reCAPTCHA from an incomplete pair.', 'checkout-firewall' ); ?></p><button class="button cf-button" type="button" disabled><?php esc_html_e( 'Test connection and enable reCAPTCHA', 'checkout-firewall' ); ?></button></div>
				<?php endif; ?>
			</div>
		</section>
		<?php
	}

	private function turnstile_settings(): void {
		$credentials = $this->turnstile->credentials();
		$conflict    = $this->conflicts->active_slug();
		$test_pair   = TurnstileConfig::is_test_pair( $credentials );
		$configured  = '' !== $credentials['site_key'] && '' !== $credentials['secret_key'];
		$active      = $this->turnstile->is_active() && null === $conflict;
		$selected    = ChallengeConfig::TURNSTILE === $this->challenges->selected();
		$eyebrow     = $test_pair ? __( 'TEST KEYS · NOT FOR PRODUCTION', 'checkout-firewall' ) : ( $active ? __( 'ALLOW · VERIFIED', 'checkout-firewall' ) : ( $selected ? __( 'CHALLENGE · SETUP REQUIRED', 'checkout-firewall' ) : __( 'OPTIONAL PROVIDER', 'checkout-firewall' ) ) );
		$status      = $active ? __( 'VERIFIED', 'checkout-firewall' ) : ( $configured ? __( 'KEYS SAVED · TEST REQUIRED', 'checkout-firewall' ) : __( 'SETUP REQUIRED', 'checkout-firewall' ) );
		?>
		<section class="cf-panel" aria-labelledby="cf-turnstile-title"><div class="cf-panel__heading"><div><p class="cf-eyebrow"><?php echo esc_html( $eyebrow ); ?></p><h3 id="cf-turnstile-title"><?php esc_html_e( 'Cloudflare Turnstile', 'checkout-firewall' ); ?></h3><p><?php esc_html_e( 'Turnstile gives an uncertain-looking legitimate customer a way to verify instead of being turned away. It appears only for recoverable challenges or Emergency Mode.', 'checkout-firewall' ); ?></p></div><span class="cf-pill <?php echo $active ? 'cf-pill--allow' : ( $selected || $configured ? 'cf-pill--challenge' : 'cf-pill--neutral' ); ?>"><?php echo esc_html( $status ); ?></span></div>
		<?php
		if ( null !== $conflict ) :
			?>
			<div class="cf-notice cf-notice--challenge"><strong><?php esc_html_e( 'Turnstile conflict', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Another checkout CAPTCHA is active. Disable one plugin before verification.', 'checkout-firewall' ); ?></p></div>
		<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="<?php echo esc_attr( TurnstileSettingsController::SAVE_ACTION ); ?>" /><?php wp_nonce_field( TurnstileSettingsController::NONCE_ACTION ); ?><label for="cf-site-key"><?php esc_html_e( 'Site key', 'checkout-firewall' ); ?></label><input id="cf-site-key" name="site_key" type="text" maxlength="128" value="<?php echo esc_attr( $credentials['site_key'] ); ?>" required <?php wp_readonly( defined( 'CHECKOUT_FIREWALL_TURNSTILE_SITE_KEY' ) ); ?> /><label for="cf-secret-key"><?php esc_html_e( 'Secret key', 'checkout-firewall' ); ?></label><input id="cf-secret-key" name="secret_key" type="password" maxlength="256" value="" autocomplete="new-password" placeholder="<?php echo defined( 'CHECKOUT_FIREWALL_TURNSTILE_SECRET_KEY' ) ? esc_attr__( 'Configured in wp-config.php', 'checkout-firewall' ) : ( '' === $credentials['secret_key'] ? esc_attr__( 'Required', 'checkout-firewall' ) : esc_attr__( 'Saved — leave blank to keep it', 'checkout-firewall' ) ); ?>" <?php wp_readonly( defined( 'CHECKOUT_FIREWALL_TURNSTILE_SECRET_KEY' ) ); ?> />
		<?php if ( defined( 'CHECKOUT_FIREWALL_TURNSTILE_SITE_KEY' ) || defined( 'CHECKOUT_FIREWALL_TURNSTILE_SECRET_KEY' ) ) : ?>
			<p class="cf-help" id="cf-key-source"><?php esc_html_e( 'Read-only keys are supplied by wp-config.php and are never copied into WordPress options.', 'checkout-firewall' ); ?></p>
		<?php endif; ?>
		<p class="cf-help"><?php esc_html_e( 'Keys are stored without autoload. Saving a change disables recovery until it is verified again.', 'checkout-firewall' ); ?></p><p class="cf-help"><?php esc_html_e( 'Express-payment recovery is not yet tested for this store. If a payment sheet is interrupted, use the standard checkout button.', 'checkout-firewall' ); ?></p><div class="cf-actions"><button class="button button-primary cf-button" type="submit"><?php esc_html_e( 'Save keys', 'checkout-firewall' ); ?></button>
			<?php
			if ( '' !== $credentials['site_key'] ) :
				?>
			<button class="button cf-button" name="remove" value="1" type="submit"><?php esc_html_e( 'Remove keys', 'checkout-firewall' ); ?></button><?php endif; ?></div></form>
			<?php
			if ( $configured && null === $conflict ) :
				?>
		<p class="cf-help"><?php esc_html_e( 'This connection test loads Turnstile on this settings page and asks Cloudflare to validate the result. It does not run a checkout or payment.', 'checkout-firewall' ); ?></p><form class="cf-health cf-turnstile-health" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-site-key="<?php echo esc_attr( $credentials['site_key'] ); ?>" data-action="checkout_firewall_health" data-cdata="<?php echo esc_attr( $this->turnstile->health_cdata() ); ?>" data-load-error="<?php esc_attr_e( 'Cloudflare Turnstile could not load. Check browser privacy controls and this site’s Content Security Policy, then retry.', 'checkout-firewall' ); ?>" data-widget-error="<?php esc_attr_e( 'Cloudflare Turnstile could not complete the connection test. Reload this page and try again.', 'checkout-firewall' ); ?>"><input type="hidden" name="action" value="<?php echo esc_attr( TurnstileSettingsController::VERIFY_ACTION ); ?>" /><?php wp_nonce_field( TurnstileSettingsController::NONCE_ACTION ); ?><input type="hidden" name="health_token" value="" /><div class="cf-health__widget" aria-live="polite"></div><button class="button button-primary cf-button" type="button" data-cf-verify disabled><?php esc_html_e( 'Test connection and enable Turnstile', 'checkout-firewall' ); ?></button></form>
		<?php elseif ( ! $configured ) : ?>
			<div class="cf-notice cf-notice--challenge"><strong><?php esc_html_e( 'Turnstile connection test unavailable', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Save both the site key and secret key first. Checkout Firewall will not enable Turnstile from an incomplete pair.', 'checkout-firewall' ); ?></p><button class="button cf-button" type="button" disabled><?php esc_html_e( 'Test connection and enable Turnstile', 'checkout-firewall' ); ?></button></div>
		<?php endif; ?></section>
		<?php
	}

	private function key_settings(): void {
		$keys = new KeyStore();
		?>
		<details class="cf-panel cf-panel--spaced cf-advanced-details">
			<summary><span class="cf-advanced-details__title"><span class="cf-eyebrow"><?php esc_html_e( 'ADVANCED SECURITY SETTING', 'checkout-firewall' ); ?></span><strong id="cf-key-title"><?php esc_html_e( 'Identity key', 'checkout-firewall' ); ?></strong><small><?php esc_html_e( 'One-way fingerprinting secret. Routine rotation is not needed.', 'checkout-firewall' ); ?></small></span><span class="cf-advanced-details__meta"><span class="cf-pill <?php echo $keys->is_healthy() ? 'cf-pill--allow' : 'cf-pill--challenge'; ?>"><?php echo $keys->is_healthy() ? esc_html__( 'HEALTHY', 'checkout-firewall' ) : esc_html__( 'ATTENTION', 'checkout-firewall' ); ?></span><span aria-hidden="true">+</span></span></summary>
			<div class="cf-advanced-details__body" aria-labelledby="cf-key-title">
				<div class="cf-explainer-grid"><div><strong><?php esc_html_e( 'What is it?', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Checkout Firewall immediately converts customer IP, email, and session values into one-way fingerprints using this secret local key. It stores the fingerprints instead of the original values.', 'checkout-firewall' ); ?></p></div><div><strong><?php esc_html_e( 'Why would I rotate it?', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Only if you believe the WordPress database or this key was exposed, or trusted support specifically directs you to rotate it. Rotating it routinely provides little benefit.', 'checkout-firewall' ); ?></p></div><div><strong><?php esc_html_e( 'What changes afterward?', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'A new key protects future fingerprints and checkout proofs. Existing key versions remain so retained history and counters still work, and active blocks keep matching.', 'checkout-firewall' ); ?></p></div></div>
				<div class="cf-warning-box"><strong><?php esc_html_e( 'Before you rotate', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'This is forward rotation, not deletion. Any configured Turnstile or reCAPTCHA provider is disabled until you verify it again in Settings. This does not change WordPress passwords, payment-gateway keys, or customer accounts.', 'checkout-firewall' ); ?></p></div>
				<?php $this->form_open( 'checkout_firewall_rotate_key' ); ?><label for="cf-rotate"><?php esc_html_e( 'Type ROTATE to confirm', 'checkout-firewall' ); ?></label><input id="cf-rotate" type="text" name="confirmation" maxlength="16" autocomplete="off" /><button class="cf-button cf-button--secondary" type="submit" <?php disabled( $this->mode->is_active() ); ?>><?php esc_html_e( 'Rotate identity key', 'checkout-firewall' ); ?></button></form>
			</div>
		</details>
		<?php
	}

	private function nav( string $active ): void {
		$labels = array(
			'overview' => __( 'Overview', 'checkout-firewall' ),
			'activity' => __( 'Activity', 'checkout-firewall' ),
			'blocks'   => __( 'Blocks', 'checkout-firewall' ),
			'settings' => __( 'Settings', 'checkout-firewall' ),
			'privacy'  => __( 'Privacy & help', 'checkout-firewall' ),
		);
		?>
	<nav class="cf-tabs" aria-label="<?php esc_attr_e( 'Checkout Firewall', 'checkout-firewall' ); ?>"><ul>
		<?php
		foreach ( $labels as $view => $label ) :
			?>
	<li><a
			<?php
			if ( $active === $view ) :
				?>
	aria-current="page"<?php endif; ?> href="
			<?php
			echo esc_url(
				add_query_arg(
					array(
						'page' => self::SLUG,
						'view' => $view,
					),
					admin_url( 'admin.php' )
				)
			);
			?>
	"><?php echo esc_html( $label ); ?></a></li><?php endforeach; ?></ul></nav>
		<?php
	}
	private function form_open( string $action, int $row_id = 0 ): void {

		?>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="<?php echo esc_attr( $action ); ?>" /><?php wp_nonce_field( AdminActionController::nonce_action( $action, $row_id ) ); ?>
		<?php
	}
	private function legal(): void {

		?>
	<p class="cf-legal"><strong><?php esc_html_e( 'A Codeprint product.', 'checkout-firewall' ); ?></strong> <?php esc_html_e( 'Checkout Firewall is an independent Codeprint product, not affiliated with or endorsed by Automattic Inc., Cloudflare, Google, or ALTCHA. WooCommerce, Cloudflare, Turnstile, Google, reCAPTCHA, and ALTCHA are trademarks of their respective owners.', 'checkout-firewall' ); ?></p>
		<?php
	}
	private function view(): string {
		$input = \Codeprint\CheckoutFirewall\Security\RequestNormalizer::query( 'view', 16, '/^[a-z]+$/D' );
		$view  = $input['invalid'] || null === $input['value'] ? 'overview' : $input['value'];
		return in_array( $view, self::VIEWS, true ) ? $view : 'overview'; }
	private function get_date( string $key ): ?string {
		$input = \Codeprint\CheckoutFirewall\Security\RequestNormalizer::query( $key, 19, '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D' );
		return $input['invalid'] ? null : $input['value']; }
	private function get_id( string $key ): ?int {
		$input = \Codeprint\CheckoutFirewall\Security\RequestNormalizer::query( $key, 20, '/^\d+$/D' );
		$value = $input['invalid'] || null === $input['value'] ? 0 : absint( $input['value'] );
		return $value > 0 ? $value : null; }
	private function date( string $gmt ): string {
		$timestamp = strtotime( $gmt . ' UTC' );
		return false === $timestamp ? $gmt : wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp ); }
	private function remaining( string $gmt ): string {
		$timestamp = strtotime( $gmt . ' UTC' );
		$seconds   = false === $timestamp ? 0 : max( 0, $timestamp - time() );
		$hours     = intdiv( $seconds, HOUR_IN_SECONDS );
		$minutes   = intdiv( $seconds % HOUR_IN_SECONDS, MINUTE_IN_SECONDS );
		/* translators: 1: whole hours remaining, 2: whole minutes remaining. */
		return sprintf( __( 'It expires in %1$d h %2$d m.', 'checkout-firewall' ), $hours, $minutes );
	}
	/**
	 * Resolve the approved masked display value.
	 *
	 * @param array<string,mixed> $row Repository row.
	 */
	private function hint( array $row ): string {
		return isset( $row['display_hint'] ) && is_string( $row['display_hint'] ) && '' !== $row['display_hint'] ? $row['display_hint'] : IdentityMasker::label( (int) ( $row['identifier_type'] ?? 0 ) ); }
	private function explanation( string $reason ): string {
		try {
			return ReasonCatalog::admin_explanation( $reason );
		} catch ( \Throwable $exception ) {
			return __( 'A local checkout protection rule intervened.', 'checkout-firewall' ); } }

	/**
	 * Render a safe trusted-exemption label.
	 *
	 * @param array<string,mixed> $row Trusted exemption row.
	 */
	private function exemption_label( array $row ): string {
		if ( 'user' === ( $row['subject_type'] ?? '' ) ) {
			$user = function_exists( 'get_userdata' ) ? get_userdata( (int) ( $row['user_id'] ?? 0 ) ) : false;
			/* translators: %d: WordPress user ID. */
			return false !== $user && isset( $user->display_name ) ? sprintf( '%s (#%d)', (string) $user->display_name, (int) $row['user_id'] ) : sprintf( __( 'WordPress user #%d', 'checkout-firewall' ), (int) ( $row['user_id'] ?? 0 ) );
		}
		return isset( $row['hint'] ) && is_string( $row['hint'] ) ? $row['hint'] : __( 'Trusted network', 'checkout-firewall' );
	}

	private function exemption_reason( string $reason ): string {
		$labels = array(
			'office_network'     => __( 'Office network', 'checkout-firewall' ),
			'wholesale_customer' => __( 'Wholesale customer', 'checkout-firewall' ),
			'vip_customer'       => __( 'VIP customer', 'checkout-firewall' ),
			'testing'            => __( 'Authorized testing', 'checkout-firewall' ),
		);
		return $labels[ $reason ] ?? __( 'Trusted exemption', 'checkout-firewall' );
	}

	private function view_url( string $view ): string {
		return add_query_arg(
			array(
				'page' => self::SLUG,
				'view' => in_array( $view, self::VIEWS, true ) ? $view : 'overview',
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Read a bounded set of recent intervention rows for the overview.
	 *
	 * @return list<array<string,mixed>>
	 */
	private function recent_events( int $limit ): array {
		try {
			return ( new EventRepository() )->page( null, null, min( 51, max( 1, $limit ) ) );
		} catch ( \Throwable $exception ) {
			return array();
		}
	}

	/**
	 * Read bounded aggregate counts for retained interventions.
	 *
	 * @return array{challenges:int,blocks:int,would_challenge:int,would_block:int,identities:int,rows:int,truncated:bool}
	 */
	private function event_summary(): array {
		try {
			return ( new EventRepository() )->summary();
		} catch ( \Throwable $exception ) {
			return array(
				'challenges'      => 0,
				'blocks'          => 0,
				'would_challenge' => 0,
				'would_block'     => 0,
				'identities'      => 0,
				'rows'            => 0,
				'truncated'       => false,
			);
		}
	}

	/**
	 * Render retained-intervention summary tiles.
	 *
	 * @param array{challenges:int,blocks:int,would_challenge:int,would_block:int,identities:int,rows:int,truncated:bool} $summary Bounded repository summary.
	 */
	private function summary_tiles( array $summary ): void {
		if ( 0 === $summary['rows'] ) {
			return;
		}
		$prefix = $summary['truncated'] ? '+' : '';
		?>
		<div class="cf-summary-grid" aria-label="<?php esc_attr_e( 'Retained checkout decisions', 'checkout-firewall' ); ?>"><div><strong><?php echo esc_html( $prefix . number_format_i18n( $summary['challenges'] ) ); ?></strong><span><?php esc_html_e( 'challenges issued', 'checkout-firewall' ); ?></span></div><div><strong><?php echo esc_html( $prefix . number_format_i18n( $summary['blocks'] ) ); ?></strong><span><?php esc_html_e( 'checkout attempts stopped', 'checkout-firewall' ); ?></span></div><div><strong><?php echo esc_html( $prefix . number_format_i18n( $summary['would_challenge'] ) ); ?></strong><span><?php esc_html_e( 'would challenge', 'checkout-firewall' ); ?></span></div><div><strong><?php echo esc_html( $prefix . number_format_i18n( $summary['would_block'] ) ); ?></strong><span><?php esc_html_e( 'would stop', 'checkout-firewall' ); ?></span></div><div><strong><?php echo esc_html( $prefix . number_format_i18n( $summary['identities'] ) ); ?></strong><span><?php esc_html_e( 'distinct keyed identities', 'checkout-firewall' ); ?></span></div><div class="cf-summary-grid__note"><strong><?php esc_html_e( 'Not counted', 'checkout-firewall' ); ?></strong><span><?php echo $summary['truncated'] ? esc_html__( 'Totals cover the newest 1,000 retained aggregate rows. Ordinary successful checkouts are never logged here.', 'checkout-firewall' ) : esc_html__( 'Ordinary successful checkouts are never logged. Observed decisions did not interrupt checkout.', 'checkout-firewall' ); ?></span></div></div>
		<?php
	}

	/**
	 * Render intervention rows in the shared activity table.
	 *
	 * @param list<array<string,mixed>> $rows Repository event rows.
	 */
	private function event_table( array $rows ): void {
		?>
		<div class="cf-table-wrap"><table class="cf-table"><thead><tr><th scope="col"><?php esc_html_e( 'When', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Decision', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Why', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Identity hint', 'checkout-firewall' ); ?></th><th scope="col"><?php esc_html_e( 'Times seen', 'checkout-firewall' ); ?></th></tr></thead><tbody>
		<?php
		foreach ( $rows as $row ) :
			$throttled = ReasonCode::CHALLENGE_UNAVAILABLE === ( $row['reason_code'] ?? null );
			$observed  = true === ( $row['observed_only'] ?? false );
			$label     = $observed ? ( 'block' === ( $row['action'] ?? '' ) ? __( 'WOULD BLOCK', 'checkout-firewall' ) : __( 'WOULD CHALLENGE', 'checkout-firewall' ) ) : ( $throttled ? __( 'THROTTLED', 'checkout-firewall' ) : strtoupper( (string) $row['action'] ) );
			?>
			<tr><td data-label="<?php esc_attr_e( 'When', 'checkout-firewall' ); ?>"><?php echo esc_html( $this->date( (string) $row['last_seen_gmt'] ) ); ?></td><td data-label="<?php esc_attr_e( 'Decision', 'checkout-firewall' ); ?>"><span class="cf-pill cf-pill--<?php echo esc_attr( $observed || $throttled ? 'challenge' : strtolower( (string) $row['action'] ) ); ?>"><?php echo esc_html( $label ); ?></span>
			<?php
			if ( $observed ) :
				?>
				<small><?php esc_html_e( 'Checkout continued.', 'checkout-firewall' ); ?></small><?php endif; ?></td><td data-label="<?php esc_attr_e( 'Why', 'checkout-firewall' ); ?>"><?php echo esc_html( $this->explanation( (string) $row['reason_code'] ) ); ?><small><code><?php echo esc_html( (string) $row['reason_code'] ); ?></code></small></td><td data-label="<?php esc_attr_e( 'Identity hint', 'checkout-firewall' ); ?>"><?php echo esc_html( $this->hint( $row ) ); ?></td><td data-label="<?php esc_attr_e( 'Times seen', 'checkout-firewall' ); ?>"><?php echo esc_html( number_format_i18n( (int) $row['event_count'] ) ); ?></td></tr><?php endforeach; ?></tbody></table></div>
		<?php
	}

	private function coverage_grid( bool $recovery_ready, bool $observing = false ): void {
		$snapshot = get_option( HealthReport::OPTION, array() );
		$health   = is_array( $snapshot ) && is_array( $snapshot['components'] ?? null ) ? $snapshot['components'] : array();
		$outage   = 'attention' === ( $health['gateways']['status'] ?? null );
		$items    = array(
			array( __( 'Automated checkout requests', 'checkout-firewall' ), __( 'One-time, five-minute checkout-flow proof identifies requests that did not follow the expected storefront flow.', 'checkout-firewall' ), true, __( 'COVERED', 'checkout-firewall' ) ),
			array( __( 'Direct Store API abuse', 'checkout-firewall' ), __( 'Checkout Blocks and Store API checkout routes use the same local decision engine as Classic Checkout.', 'checkout-firewall' ), true, __( 'COVERED', 'checkout-firewall' ) ),
			array( __( 'Rapid repeated attempts', 'checkout-firewall' ), __( 'Velocity limits evaluate keyed IP, billing email, session, and combined IP-and-email identities.', 'checkout-firewall' ), true, __( 'COVERED', 'checkout-firewall' ) ),
			array( __( 'Payment-failure patterns', 'checkout-firewall' ), $outage ? __( 'Payment-failure lockouts are reduced while a gateway outcome window needs attention; other protection remains active.', 'checkout-firewall' ) : __( 'Repeated declines and other gateway failures can produce a temporary local lockout.', 'checkout-firewall' ), ! $outage, $outage ? __( 'PAUSED · GATEWAY HEALTH', 'checkout-firewall' ) : __( 'COVERED', 'checkout-firewall' ) ),
			array( __( 'Identities already blocked', 'checkout-firewall' ), __( 'An active local block is enforced before payment and cannot be bypassed by a browser challenge.', 'checkout-firewall' ), true, __( 'COVERED', 'checkout-firewall' ) ),
			array( __( 'Recoverable challenges', 'checkout-firewall' ), $recovery_ready ? __( 'A recoverable suspicious checkout can use the selected browser check instead of reaching a dead end.', 'checkout-firewall' ) : __( 'Browser challenges are disabled; recoverable limits use an accurate temporary throttle.', 'checkout-firewall' ), $recovery_ready, $recovery_ready ? __( 'COVERED', 'checkout-firewall' ) : __( 'THROTTLE ONLY', 'checkout-firewall' ) ),
		);
		?>
		<ul class="cf-coverage-grid">
		<?php
		foreach ( $items as $item ) :
			?>
			<li><span class="cf-pill <?php echo $observing || ! $item[2] ? 'cf-pill--challenge' : 'cf-pill--allow'; ?>"><?php echo $observing ? esc_html__( 'OBSERVING', 'checkout-firewall' ) : esc_html( $item[3] ); ?></span><h4><?php echo esc_html( $item[0] ); ?></h4><p><?php echo esc_html( $item[1] ); ?></p></li><?php endforeach; ?></ul>
		<?php
	}
	private function status_copy( string $status ): string {
		$copy      = array(
			'emergency_started'             => __( 'Emergency Mode started.', 'checkout-firewall' ),
			'emergency_stopped'             => __( 'Emergency Mode stopped. Standard Mode is active.', 'checkout-firewall' ),
			'emergency_unavailable'         => __( 'Emergency Mode needs an available checkout challenge provider.', 'checkout-firewall' ),
			'emergency_active'              => __( 'Stop Emergency Mode before changing challenge settings.', 'checkout-firewall' ),
			'health_checked'                => __( 'Health check completed.', 'checkout-firewall' ),
			'health_failed'                 => __( 'Health check could not complete.', 'checkout-firewall' ),
			'block_created'                 => __( 'Local block created.', 'checkout-firewall' ),
			'block_invalid'                 => __( 'The block was not created. Check the identifier and duration.', 'checkout-firewall' ),
			'block_released'                => __( 'The block was released.', 'checkout-firewall' ),
			'block_inactive'                => __( 'The block was already inactive.', 'checkout-firewall' ),
			'block_release_failed'          => __( 'The block could not be released.', 'checkout-firewall' ),
			'settings_saved'                => __( 'Operations settings saved.', 'checkout-firewall' ),
			'settings_invalid'              => __( 'Settings were not saved. Check every value.', 'checkout-firewall' ),
			'key_rotated'                   => __( 'Identifier key rotated. Verify any configured external challenge provider again.', 'checkout-firewall' ),
			'rotation_refused'              => __( 'Key rotation was refused. Stop Emergency Mode and type ROTATE.', 'checkout-firewall' ),
			'rotation_failed'               => __( 'Key rotation could not complete safely.', 'checkout-firewall' ),
			'uninstall_saved'               => __( 'Uninstall behavior saved.', 'checkout-firewall' ),
			'uninstall_constant'            => __( 'Uninstall deletion is controlled by CHECKOUT_FIREWALL_DELETE_DATA_ON_UNINSTALL.', 'checkout-firewall' ),
			'confirmation_required'         => __( 'The required confirmation was missing.', 'checkout-firewall' ),
			'observe_enabled'               => __( 'Observe Mode is active. Checkout attempts are being measured but not challenged or stopped.', 'checkout-firewall' ),
			'observe_refused'               => __( 'End Emergency Mode before switching to Observe Mode.', 'checkout-firewall' ),
			'standard_enabled'              => __( 'Standard Mode is active. New automatic decisions can now be enforced.', 'checkout-firewall' ),
			'mode_failed'                   => __( 'Protection mode could not be changed safely.', 'checkout-firewall' ),
			'exemption_created'             => __( 'Trusted exemption created.', 'checkout-firewall' ),
			'exemption_invalid'             => __( 'Trusted exemption was not created. Check the subject, range, reason, and duration.', 'checkout-firewall' ),
			'exemption_removed'             => __( 'Trusted exemption removed.', 'checkout-firewall' ),
			'exemption_inactive'            => __( 'Trusted exemption was already inactive.', 'checkout-firewall' ),
			'exemption_remove_failed'       => __( 'Trusted exemption could not be removed.', 'checkout-firewall' ),
			'saved'                         => __( 'Turnstile keys saved and selected. Complete the connection test below to enable Turnstile.', 'checkout-firewall' ),
			'removed'                       => __( 'Turnstile keys removed.', 'checkout-firewall' ),
			'invalid'                       => __( 'Turnstile keys were not saved. Both the site key and secret key are required for initial setup.', 'checkout-firewall' ),
			'verified'                      => __( 'Turnstile recovery is verified and active.', 'checkout-firewall' ),
			'test_keys'                     => __( 'Cloudflare test keys cannot activate production checkout.', 'checkout-firewall' ),
			'invalid_secret'                => __( 'Cloudflare rejected the Turnstile secret key.', 'checkout-firewall' ),
			'verification_failed'           => __( 'Turnstile verification failed. Try again.', 'checkout-firewall' ),
			'challenge_selected'            => __( 'Checkout challenge provider saved.', 'checkout-firewall' ),
			'challenge_policy_saved'        => __( 'Checkout challenge timing saved.', 'checkout-firewall' ),
			'challenge_invalid'             => __( 'The checkout challenge provider was not changed.', 'checkout-firewall' ),
			'recaptcha_saved'               => __( 'reCAPTCHA keys saved and selected. Complete the connection test below to enable reCAPTCHA.', 'checkout-firewall' ),
			'recaptcha_removed'             => __( 'reCAPTCHA keys removed.', 'checkout-firewall' ),
			'recaptcha_invalid'             => __( 'reCAPTCHA keys were not saved. Both the site key and secret key are required for initial setup.', 'checkout-firewall' ),
			'recaptcha_verified'            => __( 'Google reCAPTCHA is verified and selected.', 'checkout-firewall' ),
			'recaptcha_invalid_secret'      => __( 'Google rejected the reCAPTCHA secret key.', 'checkout-firewall' ),
			'recaptcha_verification_failed' => __( 'reCAPTCHA verification failed. Try again.', 'checkout-firewall' ),
			'licensing_unavailable'         => __( 'Licensing connection is unavailable. Free protection is unaffected.', 'checkout-firewall' ),
		);
		$extension = AdminExtensionRegistry::status_copy( $status );
		return $copy[ $status ] ?? ( $extension ?? __( 'Settings updated.', 'checkout-firewall' ) ); }
	private function health_rows(): void {
		$snapshot = get_option( HealthReport::OPTION, array() );
		$rows     = is_array( $snapshot ) && is_array( $snapshot['components'] ?? null ) ? $snapshot['components'] : array();
		$labels   = array(
			'requirements' => __( 'Runtime requirements', 'checkout-firewall' ),
			'schema'       => __( 'Database schema', 'checkout-firewall' ),
			'keys'         => __( 'Identity keys', 'checkout-firewall' ),
			'scheduler'    => __( 'Cleanup schedules', 'checkout-firewall' ),
			'challenge'    => __( 'Checkout challenge', 'checkout-firewall' ),
			'turnstile'    => __( 'Turnstile configuration', 'checkout-firewall' ),
			'emergency'    => __( 'Protection mode', 'checkout-firewall' ),
			'proxy'        => __( 'Visitor IP detection', 'checkout-firewall' ),
			'cloudflare'   => __( 'Optional edge protection', 'checkout-firewall' ),
			'mail'         => __( 'Security email', 'checkout-firewall' ),
			'operating'    => __( 'Operating mode', 'checkout-firewall' ),
			'exemptions'   => __( 'Trusted exemptions', 'checkout-firewall' ),
			'incident'     => __( 'Activity incident', 'checkout-firewall' ),
			'gateways'     => __( 'Payment gateways', 'checkout-firewall' ),
		);
		if ( array() === $rows ) {
			echo '<div class="cf-empty-state cf-empty-state--compact"><p>' . esc_html__( 'Run the bounded local protection check to verify the database, schedules, identity key, proxy policy, gateways, and checkout recovery provider.', 'checkout-firewall' ) . '</p></div>';
			return;
		}
		$checked = isset( $snapshot['checked_at_gmt'] ) && is_string( $snapshot['checked_at_gmt'] ) ? $this->date( $snapshot['checked_at_gmt'] ) : '';
		if ( '' !== $checked ) {
			/* translators: %s: localized date and time of the last health check. */
			echo '<p class="cf-health-checked">' . esc_html( sprintf( __( 'Checked %s', 'checkout-firewall' ), $checked ) ) . '</p>';
		}
		echo '<dl class="cf-health-list">';
		foreach ( $rows as $name => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			} echo '<div><dt><span class="cf-pill cf-pill--' . esc_attr( 'healthy' === ( $row['status'] ?? '' ) ? 'allow' : ( 'attention' === ( $row['status'] ?? '' ) ? 'challenge' : 'neutral' ) ) . '">' . esc_html( 'healthy' === ( $row['status'] ?? '' ) ? __( 'PASS', 'checkout-firewall' ) : ( 'attention' === ( $row['status'] ?? '' ) ? __( 'ATTENTION', 'checkout-firewall' ) : __( 'INACTIVE', 'checkout-firewall' ) ) ) . '</span></dt><dd><strong>' . esc_html( $labels[ $name ] ?? ucfirst( (string) $name ) ) . '</strong><span>' . esc_html( (string) ( $row['detail'] ?? '' ) ) . '</span></dd></div>';
		} echo '</dl>'; }
	/**
	 * Render one closed retention selector.
	 *
	 * @param list<int> $days Allowed day values.
	 */
	private function select_days( string $name, string $id, array $days, int $selected ): void {

		?>
	<select id="<?php echo esc_attr( $id ); ?>" name="<?php echo esc_attr( $name ); ?>">
		<?php
		foreach ( $days as $day ) :
			?>
		<option value="<?php echo esc_attr( (string) $day ); ?>" <?php selected( $selected, $day ); ?>><?php /* translators: %d: number of retention days. */ echo esc_html( sprintf( _n( '%d day', '%d days', $day, 'checkout-firewall' ), $day ) ); ?></option><?php endforeach; ?></select>
		<?php
	}
}
