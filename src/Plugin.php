<?php
/**
 * Runtime service coordinator.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall;

use Codeprint\CheckoutFirewall\Admin\RequirementsNotice;
use Codeprint\CheckoutFirewall\Admin\AdminActionController;
use Codeprint\CheckoutFirewall\Admin\CheckoutFirewallPage;
use Codeprint\CheckoutFirewall\Admin\SupportExportController;
use Codeprint\CheckoutFirewall\Admin\TurnstileSettingsController;
use Codeprint\CheckoutFirewall\Admin\ChallengeSettingsController;
use Codeprint\CheckoutFirewall\Admin\FreeIncidentNotice;
use Codeprint\CheckoutFirewall\Challenge\ChallengeCandidateProvider;
use Codeprint\CheckoutFirewall\Challenge\ChallengeClassicClient;
use Codeprint\CheckoutFirewall\Challenge\ChallengeConfig;
use Codeprint\CheckoutFirewall\Challenge\ChallengeCoordinator;
use Codeprint\CheckoutFirewall\Challenge\ChallengeEndpoint;
use Codeprint\CheckoutFirewall\Challenge\ChallengeInputRegistry;
use Codeprint\CheckoutFirewall\Challenge\LocalProofService;
use Codeprint\CheckoutFirewall\Compatibility\Requirements;
use Codeprint\CheckoutFirewall\Commercial\CommercialAccountController;
use Codeprint\CheckoutFirewall\Commercial\CommercialBootstrap;
use Codeprint\CheckoutFirewall\Commercial\PremiumRegistrar;
use Codeprint\CheckoutFirewall\Commercial\PremiumRuntimeContext;
use Codeprint\CheckoutFirewall\Database\Migrator;
use Codeprint\CheckoutFirewall\Database\Schema;
use Codeprint\CheckoutFirewall\Enforcement\CheckoutGuard;
use Codeprint\CheckoutFirewall\Enforcement\ClassicCheckoutAdapter;
use Codeprint\CheckoutFirewall\Enforcement\StoreApiCheckoutAdapter;
use Codeprint\CheckoutFirewall\FlowProof\CheckoutBlocksRegistrar;
use Codeprint\CheckoutFirewall\FlowProof\CheckoutEvidenceInputRegistry;
use Codeprint\CheckoutFirewall\FlowProof\CheckoutEvidenceProvider;
use Codeprint\CheckoutFirewall\FlowProof\CheckoutEvidenceService;
use Codeprint\CheckoutFirewall\FlowProof\ClassicCheckoutClient;
use Codeprint\CheckoutFirewall\FlowProof\FlowProofCandidateProvider;
use Codeprint\CheckoutFirewall\FlowProof\FlowProofInputRegistry;
use Codeprint\CheckoutFirewall\FlowProof\MintEndpoint;
use Codeprint\CheckoutFirewall\Protection\BlockRepository;
use Codeprint\CheckoutFirewall\Protection\CounterRepository;
use Codeprint\CheckoutFirewall\Protection\CheckoutSignalState;
use Codeprint\CheckoutFirewall\Protection\DecisionEventRecorder;
use Codeprint\CheckoutFirewall\Protection\EventRepository;
use Codeprint\CheckoutFirewall\Protection\EventRetentionState;
use Codeprint\CheckoutFirewall\Protection\GatewayHealth;
use Codeprint\CheckoutFirewall\Protection\GatewayObservationState;
use Codeprint\CheckoutFirewall\Protection\IdentityRegistry;
use Codeprint\CheckoutFirewall\Protection\PaymentFeedback;
use Codeprint\CheckoutFirewall\Protection\VelocityCandidateProvider;
use Codeprint\CheckoutFirewall\Protection\VelocityObservationState;
use Codeprint\CheckoutFirewall\Protection\VerifiedProofState;
use Codeprint\CheckoutFirewall\Protection\TrustedExemptionFilter;
use Codeprint\CheckoutFirewall\Protection\TrustedExemptionMatcher;
use Codeprint\CheckoutFirewall\Protection\TrustedExemptionState;
use Codeprint\CheckoutFirewall\Protection\TrustedExemptionStore;
use Codeprint\CheckoutFirewall\Operations\AttackStartMailer;
use Codeprint\CheckoutFirewall\Operations\EmergencyCandidateProvider;
use Codeprint\CheckoutFirewall\Operations\EmergencyMode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;
use Codeprint\CheckoutFirewall\Operations\FreeIncidentMailer;
use Codeprint\CheckoutFirewall\Operations\FreeIncidentObserver;
use Codeprint\CheckoutFirewall\Operations\FreeIncidentState;
use Codeprint\CheckoutFirewall\Privacy\PersonalDataEraser;
use Codeprint\CheckoutFirewall\Privacy\PrivacyPolicyContent;
use Codeprint\CheckoutFirewall\Scheduler\CleanupScheduler;
use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Support\SafeLogger;
use Codeprint\CheckoutFirewall\Recaptcha\RecaptchaConfig;
use Codeprint\CheckoutFirewall\Recaptcha\SiteverifyClient as RecaptchaSiteverifyClient;
use Codeprint\CheckoutFirewall\Turnstile\SiteverifyClient as TurnstileSiteverifyClient;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConfig;
use Codeprint\CheckoutFirewall\Turnstile\TurnstileConflictDetector;
use Codeprint\CheckoutFirewall\Turnstile\VerifiedChallengeState;

final class Plugin {
	private static bool $booted = false;

	public static function boot(): void {
		if ( self::$booted ) {
			return;
		}
		self::$booted = true;

		try {
			wp_prime_option_caches( array( Migrator::DATABASE_VERSION_OPTION, 'cwf_plugin_version', CleanupScheduler::VERSION_OPTION, EmergencyMode::OPTION, OperatingMode::OPTION ) );

			$failure = Requirements::runtime_failure();
			if ( null !== $failure ) {
				Health::record( 'requirements', $failure );
				RequirementsNotice::register( $failure );
				return;
			}

			if ( Migrator::installed_version() < Schema::VERSION ) {
				self::register_migration_path();
				return;
			}

			if ( self::is_maintenance_context() && ! self::validate_key_health() ) {
				RequirementsNotice::register( 'key_unhealthy' );
				return;
			}

			CleanupScheduler::register();
			$proof_inputs      = new FlowProofInputRegistry();
			$evidence_inputs   = new CheckoutEvidenceInputRegistry();
			$evidence_service  = new CheckoutEvidenceService();
			$checkout_signals  = new CheckoutSignalState();
			$verified          = new VerifiedProofState();
			$identities        = new IdentityRegistry();
			$counters          = new CounterRepository();
			$operating         = new OperatingMode();
			$blocks            = new BlockRepository( null, $operating );
			$exemption_store   = new TrustedExemptionStore();
			$exemption_matcher = new TrustedExemptionMatcher( $exemption_store );
			$exemption_state   = new TrustedExemptionState();
			$exemption_store->register();
			$gateway_observations  = new GatewayObservationState();
			$event_retention       = new EventRetentionState();
			$health                = new GatewayHealth( $counters, $identities, $gateway_observations );
			$turnstile_config      = new TurnstileConfig();
			$recaptcha_config      = new RecaptchaConfig();
			$turnstile_conflicts   = new TurnstileConflictDetector();
			$challenge_config      = new ChallengeConfig( $turnstile_config, $recaptcha_config, $turnstile_conflicts );
			$challenge_inputs      = new ChallengeInputRegistry();
			$turnstile_verified    = new VerifiedChallengeState();
			$velocity_observations = new VelocityObservationState();
			$emergency             = new EmergencyMode( $turnstile_config, $turnstile_conflicts, null, null, $challenge_config, $operating );
			$mailer                = new AttackStartMailer();
			$incident_state        = new FreeIncidentState();
			$incident_mailer       = new FreeIncidentMailer( $incident_state, $mailer );
			$incident_observer     = new FreeIncidentObserver( $counters, $incident_state, $incident_mailer );
			$shared_events         = new EventRepository( null, $event_retention );
			$feedback              = new PaymentFeedback( $counters, $blocks, $health, $operating, $exemption_matcher, $shared_events, $incident_observer );
			$local_challenge       = new LocalProofService();
			$challenges            = new ChallengeCoordinator( $challenge_config, $local_challenge );
			( new ChallengeCandidateProvider( $challenge_inputs, $challenge_config, $challenges, $local_challenge, new TurnstileSiteverifyClient(), new RecaptchaSiteverifyClient(), $turnstile_verified, $emergency ) )->register();
			( new EmergencyCandidateProvider( $emergency, $turnstile_config, $turnstile_conflicts, $turnstile_verified, $challenge_config ) )->register();
			( new FlowProofCandidateProvider( $proof_inputs, null, null, $verified, $turnstile_verified ) )->register();
			( new CheckoutEvidenceProvider( $evidence_inputs, $evidence_service, $checkout_signals ) )->register();
			( new VelocityCandidateProvider( $verified, $identities, $counters, $blocks, $health, $turnstile_verified, $velocity_observations, $checkout_signals ) )->register();
			( new TrustedExemptionFilter( $exemption_matcher, $exemption_state ) )->register();
			$feedback->register();
			( new MintEndpoint( null, $evidence_service ) )->register();
			( new ChallengeEndpoint( $challenges ) )->register();
			( new ClassicCheckoutClient() )->register();
			( new ChallengeClassicClient() )->register();
			( new CheckoutBlocksRegistrar() )->register();
			$emergency->register();
			$mailer->register();
			$incident_mailer->register();
			$incident_observer->register();
			( new FreeIncidentNotice( $incident_state ) )->register();
			( new CheckoutFirewallPage( $turnstile_config, $turnstile_conflicts, $emergency, $challenge_config, $recaptcha_config, $operating, $exemption_store ) )->register();
			( new AdminActionController( $emergency, $mailer, $operating, $exemption_store ) )->register();
			( new SupportExportController() )->register();
			( new TurnstileSettingsController( $turnstile_config, null, $challenge_config ) )->register();
			( new ChallengeSettingsController( $challenge_config, $recaptcha_config, $emergency ) )->register();
			( new PersonalDataEraser() )->register();
			( new PrivacyPolicyContent() )->register();
			( new CommercialAccountController() )->register();
			$events = new DecisionEventRecorder( $shared_events, $identities, $incident_observer );
			$guard  = new CheckoutGuard( null, null, $events, $challenges, $operating );
			( new ClassicCheckoutAdapter( $guard, $proof_inputs, $identities, $feedback, null, $challenge_inputs, $evidence_inputs ) )->register();
			( new StoreApiCheckoutAdapter( $guard, $proof_inputs, $identities, $feedback, null, $challenge_inputs, $evidence_inputs ) )->register();
			PremiumRegistrar::register(
				CommercialBootstrap::provider(),
				new PremiumRuntimeContext( $verified, $turnstile_verified, $velocity_observations, $turnstile_config, $turnstile_conflicts, $emergency, $gateway_observations, $event_retention, $challenge_config )
			);
		} catch ( \Throwable $exception ) {
			SafeLogger::exception( 'runtime_boot_failed', $exception );
			if ( is_admin() ) {
				RequirementsNotice::register( 'schema_unhealthy' );
			}
		}
	}

	public static function migrate_from_admin(): void {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}

		self::migrate_and_initialize();
	}

	private static function register_migration_path(): void {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			self::migrate_and_initialize();
			return;
		}

		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			self::migrate_and_initialize();
			return;
		}

		if ( is_admin() && ! wp_doing_ajax() ) {
			RequirementsNotice::register( 'schema_outdated' );
			add_action( 'admin_init', array( self::class, 'migrate_from_admin' ) );
		}
	}

	private static function migrate_and_initialize(): void {
		$migrator = new Migrator();
		if ( ! $migrator->migrate() ) {
			RequirementsNotice::register( 'schema_unhealthy' );
			return;
		}

		$key_store = new KeyStore();
		if ( ! $key_store->initialize() || ! $key_store->validate_references() ) {
			Health::record( 'key', 'verification_failed' );
			RequirementsNotice::register( 'key_unhealthy' );
			return;
		}

		Migrator::write_option( 'cwf_plugin_version', CWF_VERSION );
		CleanupScheduler::register();
		if ( class_exists( '\\ActionScheduler' ) && \ActionScheduler::is_initialized() ) {
			CleanupScheduler::ensure_schedules();
		}
	}

	private static function validate_key_health(): bool {
		$key_store = new KeyStore();
		if ( ! $key_store->is_healthy() || ! $key_store->validate_references() ) {
			Health::record( 'key', 'verification_failed' );
			return false;
		}

		Health::clear( 'key' );
		return true;
	}

	private static function is_maintenance_context(): bool {
		return is_admin()
			|| ( defined( 'WP_CLI' ) && WP_CLI )
			|| ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() );
	}
}
