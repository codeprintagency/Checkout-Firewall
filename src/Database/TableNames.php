<?php
/**
 * Trusted Checkout Firewall table names.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Database;

final class TableNames {
	private const SUFFIXES = array(
		'events'          => 'cwf_events',
		'counters'        => 'cwf_counters',
		'blocks'          => 'cwf_blocks',
		'consumed_tokens' => 'cwf_consumed_tokens',
	);

	private string $prefix;

	public function __construct( string $prefix ) {
		if ( 1 !== preg_match( '/^[A-Za-z0-9_]+$/D', $prefix ) ) {
			throw new \InvalidArgumentException( 'Invalid WordPress database table prefix.' );
		}

		$this->prefix = $prefix;
	}

	public static function from_wordpress(): self {
		global $wpdb;
		return new self( (string) $wpdb->prefix );
	}

	public function get( string $logical_name ): string {
		if ( ! isset( self::SUFFIXES[ $logical_name ] ) ) {
			throw new \InvalidArgumentException( 'Unknown Checkout Firewall table.' );
		}

		return $this->prefix . self::SUFFIXES[ $logical_name ];
	}

	/**
	 * Resolve every allowlisted table.
	 *
	 * @return array<string, string>
	 */
	public function all(): array {
		$tables = array();
		foreach ( array_keys( self::SUFFIXES ) as $logical_name ) {
			$tables[ $logical_name ] = $this->get( $logical_name );
		}

		return $tables;
	}
}
