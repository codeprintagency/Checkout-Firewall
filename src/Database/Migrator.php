<?php
/**
 * Idempotent additive schema migration.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Database;

use Codeprint\CheckoutFirewall\Support\Health;

final class Migrator {
	public const DATABASE_VERSION_OPTION = 'checkout_firewall_db_version';

	private Schema $schema;
	private MigrationLock $lock;

	public function __construct( ?Schema $schema = null, ?MigrationLock $lock = null ) {
		$this->schema = $schema ?? new Schema( TableNames::from_wordpress() );
		$this->lock   = $lock ?? new MigrationLock();
	}

	public static function installed_version(): int {
		return max( 0, (int) get_option( self::DATABASE_VERSION_OPTION, 0 ) );
	}

	public function migrate(): bool {
		global $wpdb;

		if ( ! $this->lock->acquire() ) {
			Health::record( 'schema', 'migration_locked' );
			return false;
		}

		try {
			if ( ! $this->lock->owns_lock() ) {
				Health::record( 'schema', 'migration_lock_lost' );
				return false;
			}

			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			foreach ( $this->schema->definitions() as $definition ) {
				$changes = dbDelta( $definition );
				if ( ! is_array( $changes ) ) {
					Health::record( 'schema', 'dbdelta_failed' );
					return false;
				}
			}

			$issues = $this->schema->verify();
			if ( array() !== $issues ) {
				Health::record( 'schema', 'verification_failed' );
				return false;
			}

			self::write_option( self::DATABASE_VERSION_OPTION, Schema::VERSION );
			Health::clear( 'schema' );
			return true;
		} catch ( \Throwable $exception ) {
			Health::record( 'schema', 'migration_exception' );
			return false;
		} finally {
			$this->lock->release();
		}
	}

	/**
	 * Write a non-autoloaded plugin option.
	 *
	 * @param mixed $value Option value.
	 */
	public static function write_option( string $name, $value ): void {
		if ( false === get_option( $name, false ) ) {
			add_option( $name, $value, '', false );
			return;
		}

		update_option( $name, $value, false );
	}
}
