<?php
/**
 * Branded non-checkout pricing page backed by Freemius checkout URLs.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

final class CommercialUpgradePage {
	private object $sdk;
	private EntitlementProvider $provider;

	public function __construct( object $sdk, EntitlementProvider $provider ) {
		$this->sdk      = $sdk;
		$this->provider = $provider;
	}

	/**
	 * Register only the supported Freemius pricing-template filter.
	 */
	public static function register( object $sdk, EntitlementProvider $provider ): bool {
		if ( ! method_exists( $sdk, 'add_filter' )
			|| ! method_exists( $sdk, 'checkout_url' )
			|| ! method_exists( $sdk, 'get_account_url' )
		) {
			return false;
		}

		$page = new self( $sdk, $provider );
		$sdk->add_filter( 'templates/pricing.php', array( $page, 'render' ), 10, 1 );
		add_action( 'admin_enqueue_scripts', array( $page, 'assets' ) );
		return true;
	}

	/**
	 * Load the branded stylesheet only for the non-checkout Upgrade page.
	 */
	public function assets( string $hook ): void {
		if ( 'woocommerce_page_checkout-firewall-pricing' !== $hook
			|| true === filter_input( INPUT_GET, 'checkout', FILTER_VALIDATE_BOOLEAN )
		) {
			return;
		}

		wp_enqueue_style(
			'checkout-firewall-upgrade',
			plugins_url( 'assets/css/checkout-firewall-upgrade.css', CWF_PLUGIN_FILE ),
			array(),
			CWF_VERSION
		);
		wp_dequeue_script( 'freemius-pricing' );
		wp_dequeue_script( 'fs-postmessage' );
		wp_dequeue_script( 'postmessage' );
		wp_dequeue_style( 'freemius-pricing' );
	}

	/**
	 * Replace only the non-checkout pricing template.
	 */
	public function render( string $original ): string {
		try {
			if ( ! current_user_can( 'manage_options' ) ) {
				return $original;
			}

			$entitlement = $this->provider->entitlement();
			$current     = Entitlement::ACTIVE_PAID === $entitlement->state() && $entitlement->allows_premium()
				? $entitlement->plan()
				: '';
			$plans       = $this->plans( $current );
			$account_url = (string) $this->sdk->get_account_url();
			if ( 3 !== count( $plans ) || '' === $account_url ) {
				return $original;
			}

			ob_start();
			$this->markup( $plans, $current, $account_url );
			$html = ob_get_clean();
			return is_string( $html ) && '' !== $html ? $html : $original;
		} catch ( \Throwable $exception ) {
			unset( $exception );
			return $original;
		}
	}

	/**
	 * Build the three released annual plan choices.
	 *
	 * @return list<array<string,mixed>>
	 */
	private function plans( string $current ): array {
		$plans = array(
			array(
				'id'         => 'pro',
				'name'       => __( 'Pro', 'checkout-firewall' ),
				'price'      => '$59',
				'sites'      => __( '1 store', 'checkout-firewall' ),
				'per_store'  => __( '$59.00 per store / year', 'checkout-firewall' ),
				'blurb'      => __( 'A single serious store that wants protection to adapt on its own.', 'checkout-firewall' ),
				'pricing_id' => 80057,
			),
			array(
				'id'         => 'business',
				'name'       => __( 'Business', 'checkout-firewall' ),
				'price'      => '$119',
				'sites'      => __( 'Up to 5 stores', 'checkout-firewall' ),
				'per_store'  => __( '$23.80 per store / year', 'checkout-firewall' ),
				'blurb'      => __( 'Merchants, developers, and small agencies running several stores.', 'checkout-firewall' ),
				'pricing_id' => 80058,
			),
			array(
				'id'         => 'agency',
				'name'       => __( 'Agency', 'checkout-firewall' ),
				'price'      => '$199',
				'sites'      => __( 'Up to 25 stores', 'checkout-firewall' ),
				'per_store'  => __( '$7.96 per store / year', 'checkout-firewall' ),
				'blurb'      => __( 'Agencies and operators protecting a larger client portfolio.', 'checkout-firewall' ),
				'pricing_id' => 80059,
			),
		);

		foreach ( $plans as &$plan ) {
			$plan['current'] = $current === $plan['id'];
			$plan['url']     = (string) $this->sdk->checkout_url(
				'annual',
				false,
				array( 'pricing_id' => $plan['pricing_id'] )
			);
			if ( '' === $plan['url'] ) {
				return array();
			}
		}
		unset( $plan );

		return $plans;
	}

	/**
	 * Render the complete Upgrade page without changing the Freemius checkout.
	 *
	 * @param list<array<string,mixed>> $plans Released annual plans.
	 */
	private function markup( array $plans, string $current, string $account_url ): void {
		$premium_groups = array(
			__( 'Automatic Normal, Elevated, Attack, and Recovery protection states', 'checkout-firewall' ),
			__( 'Adaptive velocity thresholds during an escalating attack', 'checkout-firewall' ),
			__( 'Automatic guest-checkout challenge escalation when a healthy provider is available', 'checkout-firewall' ),
			__( 'Distributed identity-rotation detection for coordinated abuse', 'checkout-firewall' ),
			__( 'Corroboration across checkout proof, velocity, blocks, and safe gateway-failure signals', 'checkout-firewall' ),
		);
		$operations     = array(
			__( '90-day local intervention analytics', 'checkout-firewall' ),
			__( 'Incident history and operational timelines', 'checkout-firewall' ),
			__( 'CSV analytics export', 'checkout-firewall' ),
			__( 'Expanded redacted diagnostics', 'checkout-firewall' ),
		);
		$alerts         = array(
			__( 'Slack, Discord, and generic webhook alerts', 'checkout-firewall' ),
			__( 'Encrypted alert destinations with asynchronous delivery', 'checkout-firewall' ),
			__( 'Protection-policy export, preview, and import', 'checkout-firewall' ),
			__( 'Premium feature labels and active-plan visibility throughout the plugin', 'checkout-firewall' ),
		);
		$free_items     = array(
			__( 'Seven-day Observe Mode for evaluating protection before enforcing it', 'checkout-firewall' ),
			__( 'Standard enforcement and time-boxed Emergency Mode', 'checkout-firewall' ),
			__( 'Checkout-flow proof, randomized honeypot, and timing signals', 'checkout-firewall' ),
			__( 'Local velocity and repeated payment-failure controls', 'checkout-firewall' ),
			__( 'Classic Checkout, Checkout Blocks, and supported Store API checkout routes', 'checkout-firewall' ),
			__( 'Private local browser challenge — no account or API keys', 'checkout-firewall' ),
			__( 'Optional Cloudflare Turnstile and Google reCAPTCHA v2', 'checkout-firewall' ),
			__( 'Automatic direct and Cloudflare visitor-address detection', 'checkout-firewall' ),
			__( 'Manual blocks, block release, and trusted exemptions', 'checkout-firewall' ),
			__( 'Local Activity, Protection Health, privacy controls, and support diagnostics', 'checkout-firewall' ),
			__( 'Sustained-attack dashboard notices and optional WordPress email', 'checkout-firewall' ),
			__( 'No card-data access and no security telemetry sent to Codeprint or Freemius', 'checkout-firewall' ),
		);
		?>
		<div class="wrap cf-upgrade">
			<section class="cf-upgrade__hero" aria-labelledby="cf-upgrade-title">
				<p class="cf-upgrade__eyebrow"><?php esc_html_e( 'Free vs Premium', 'checkout-firewall' ); ?></p>
				<h1 id="cf-upgrade-title"><?php esc_html_e( 'All paid plans include the complete Premium feature set. Choose a plan based only on how many stores you protect.', 'checkout-firewall' ); ?></h1>
				<div class="cf-upgrade__contrast">
					<div><strong><?php esc_html_e( 'FREE — YOU DIRECT IT', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'Local checkout protection with fixed rules. It enforces what you configure, and you decide when to escalate — Emergency Mode is a switch you throw yourself.', 'checkout-firewall' ); ?></p></div>
					<div><strong><?php esc_html_e( 'PREMIUM — IT ADAPTS', 'checkout-firewall' ); ?></strong><p><?php esc_html_e( 'The same local engine, plus automatic escalation and recovery, distributed-abuse detection, 90-day analytics, alerts, and policy transfer — so you are not watching the log at 2am.', 'checkout-firewall' ); ?></p></div>
				</div>
				<p class="cf-upgrade__fine-print"><?php esc_html_e( 'The Premium engine stays local and deterministic. It does not use remote fraud scoring, does not inspect card data, and never disables a payment gateway.', 'checkout-firewall' ); ?></p>
			</section>

			<section class="cf-upgrade__section" aria-labelledby="cf-upgrade-plans">
				<header class="cf-upgrade__section-heading"><h2 id="cf-upgrade-plans"><?php esc_html_e( 'Pick by store count', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'Identical features on every paid plan · annual billing · 14-day refund', 'checkout-firewall' ); ?></p></header>
				<div class="cf-upgrade__plans">
					<?php foreach ( $plans as $plan ) : ?>
						<article class="cf-upgrade__plan <?php echo esc_attr( 'pro' === $plan['id'] ? 'cf-upgrade__plan--popular' : '' ); ?> <?php echo esc_attr( $plan['current'] ? 'cf-upgrade__plan--current' : '' ); ?>" <?php if ( $plan['current'] ) : ?>
							aria-current="page"
						<?php endif; ?>>
							<div class="cf-upgrade__plan-heading"><h3><?php echo esc_html( (string) $plan['name'] ); ?></h3>
							<?php
							if ( 'pro' === $plan['id'] ) :
								?>
								<span><?php esc_html_e( 'MOST POPULAR', 'checkout-firewall' ); ?></span><?php endif; ?>
								<?php
								if ( $plan['current'] ) :
									?>
								<span><?php esc_html_e( 'CURRENT PLAN', 'checkout-firewall' ); ?></span><?php endif; ?></div>
							<p class="cf-upgrade__price"><?php echo esc_html( (string) $plan['price'] ); ?><small><?php esc_html_e( ' /year', 'checkout-firewall' ); ?></small></p>
							<p class="cf-upgrade__sites"><?php echo esc_html( (string) $plan['sites'] ); ?><br><?php echo esc_html( (string) $plan['per_store'] ); ?></p>
							<p><?php echo esc_html( (string) $plan['blurb'] ); ?></p>
							<?php if ( $plan['current'] ) : ?>
								<a class="cf-upgrade__cta cf-upgrade__cta--primary" href="<?php echo esc_url( $account_url ); ?>"><?php esc_html_e( 'Manage current plan', 'checkout-firewall' ); ?></a>
							<?php else : ?>
								<a class="cf-upgrade__cta <?php echo esc_attr( 'pro' === $plan['id'] ? 'cf-upgrade__cta--primary' : '' ); ?>" href="<?php echo esc_url( (string) $plan['url'] ); ?>">
								<?php
								// translators: %s is the public paid-plan name.
								echo esc_html( sprintf( __( 'Choose %s', 'checkout-firewall' ), (string) $plan['name'] ) );
								?>
								</a>
							<?php endif; ?>
						</article>
					<?php endforeach; ?>
				</div>
				<p class="cf-upgrade__note"><?php esc_html_e( 'Business and Agency do not unlock anything Pro lacks — they lower the cost per store. Recognised local, development, and staging installs do not consume production activations.', 'checkout-firewall' ); ?></p>
			</section>

			<section class="cf-upgrade__section" aria-labelledby="cf-upgrade-premium-features">
				<header class="cf-upgrade__section-heading"><h2 id="cf-upgrade-premium-features"><?php esc_html_e( 'What every paid plan adds', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'Everything in Free, plus all of the below', 'checkout-firewall' ); ?></p></header>
				<div class="cf-upgrade__feature-groups">
					<?php $this->feature_group( __( 'Automatic protection', 'checkout-firewall' ), $premium_groups ); ?>
					<?php $this->feature_group( __( 'Operational visibility', 'checkout-firewall' ), $operations ); ?>
					<?php $this->feature_group( __( 'Alerts and transfer', 'checkout-firewall' ), $alerts ); ?>
				</div>
			</section>

			<section class="cf-upgrade__section" aria-labelledby="cf-upgrade-free-features">
				<header class="cf-upgrade__section-heading"><h2 id="cf-upgrade-free-features"><?php esc_html_e( 'What you already have on Free', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'Included on every plan · a real protection product, not a demo', 'checkout-firewall' ); ?></p></header>
				<div class="cf-upgrade__free"><ul>
				<?php
				foreach ( $free_items as $item ) :
					?>
					<li><span aria-hidden="true">+</span><span><?php echo esc_html( $item ); ?></span></li><?php endforeach; ?></ul></div>
			</section>

			<section class="cf-upgrade__assurances" aria-label="<?php esc_attr_e( 'Plan assurances', 'checkout-firewall' ); ?>">
				<div><h2><?php esc_html_e( 'If a licence lapses', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'Free protection keeps running with your settings and history intact. Automatic states, alerts, and 90-day analytics stop until you renew.', 'checkout-firewall' ); ?></p></div>
				<div><h2><?php esc_html_e( 'Moving between plans', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'Changing plan changes only your activation allowance — no feature is added or taken away. Payment, tax, and licensing are handled by Freemius.', 'checkout-firewall' ); ?></p></div>
				<div><h2><?php esc_html_e( 'What we still will not do', 'checkout-firewall' ); ?></h2><p><?php esc_html_e( 'No card-data access, no remote fraud scoring, no security telemetry leaving your server, and no automatic disabling of a payment gateway — on any plan.', 'checkout-firewall' ); ?></p></div>
			</section>
			<?php
			if ( '' !== $current ) :
				?>
				<p class="cf-upgrade__account"><a href="<?php echo esc_url( $account_url ); ?>"><?php esc_html_e( 'Open licensing account', 'checkout-firewall' ); ?></a></p><?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render one accessible Premium feature group.
	 *
	 * @param list<string> $items Feature descriptions.
	 */
	private function feature_group( string $title, array $items ): void {
		?>
		<div class="cf-upgrade__feature-group"><h3><?php echo esc_html( $title ); ?></h3><ul>
		<?php
		foreach ( $items as $item ) :
			?>
			<li><span aria-hidden="true">+</span><span><?php echo esc_html( $item ); ?></span></li><?php endforeach; ?></ul></div>
		<?php
	}
}
