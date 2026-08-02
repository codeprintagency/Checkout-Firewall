<?php
/**
 * Validated generated Freemius configuration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Commercial;

use Codeprint\CheckoutFirewall\Premium\BuildSentinel;

final class FreemiusConfig {
	private const PLACEHOLDER_MARKER = 'PLACEHOLDER';
	private const PLANS              = array( 'pro', 'business', 'agency' );

	/**
	 * Generated build configuration.
	 *
	 * @var array<string,mixed>
	 */
	private array $values;

	/**
	 * Create a validated configuration wrapper.
	 *
	 * @param array<string,mixed> $values Generated build configuration.
	 */
	public function __construct( array $values ) {
		$this->values = $values;
	}

	public static function load( string $project_directory ): self {
		$file = rtrim( $project_directory, '/\\' ) . '/config/checkout-firewall-build.php';
		if ( ! is_readable( $file ) ) {
			return new self( array() );
		}
		$values = require $file;
		return new self( is_array( $values ) ? $values : array() );
	}

	public function code_type(): string {
		$configured = CodeType::normalize( $this->scalar( 'code_type' ) );
		if ( CodeType::PREMIUM === $configured && ! class_exists( BuildSentinel::class ) ) {
			return CodeType::FREE;
		}
		return $configured;
	}

	public function is_configured(): bool {
		$id  = $this->scalar( 'product_id' );
		$key = $this->scalar( 'public_key' );
		return '' !== $id
			&& ctype_digit( $id )
			&& 0 < (int) $id
			&& 1 === preg_match( '/^pk_[A-Za-z0-9]+$/D', $key )
			&& false === strpos( $id . $key, self::PLACEHOLDER_MARKER );
	}

	public function product_id(): string {
		return $this->scalar( 'product_id' );
	}

	public function public_key(): string {
		return $this->scalar( 'public_key' );
	}

	public function premium_slug(): string {
		$value = $this->scalar( 'premium_slug' );
		return 'checkout-firewall-premium' === $value ? $value : 'checkout-firewall-premium';
	}

	/**
	 * Return the closed paid-plan allowlist.
	 *
	 * @return list<string>
	 */
	public function plans(): array {
		$plans = $this->values['plans'] ?? array();
		if ( ! is_array( $plans ) || array_values( $plans ) !== self::PLANS ) {
			return self::PLANS;
		}
		return self::PLANS;
	}

	/**
	 * Return the early Freemius initializer parameters.
	 *
	 * @return array<string,mixed>
	 */
	public function sdk_parameters(): array {
		return array(
			'id'                  => $this->product_id(),
			'slug'                => 'checkout-firewall',
			'premium_slug'        => $this->premium_slug(),
			'type'                => 'plugin',
			'public_key'          => $this->public_key(),
			'is_premium'          => CodeType::PREMIUM === $this->code_type(),
			'has_premium_version' => true,
			'has_paid_plans'      => true,
			'is_org_compliant'    => true,
			'anonymous_mode'      => true,
			'has_affiliation'     => false,
			'permissions'         => array(
				'newsletter' => false,
				'diagnostic' => false,
				'extensions' => false,
			),
			'menu'                => array(
				'slug'       => 'checkout-firewall',
				'first-path' => 'admin.php?page=checkout-firewall',
				'parent'     => array( 'slug' => 'woocommerce' ),
			),
		);
	}

	private function scalar( string $key ): string {
		$value = $this->values[ $key ] ?? '';
		return is_string( $value ) ? $value : '';
	}
}
