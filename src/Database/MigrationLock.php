<?php
/**
 * Compare-and-swap migration lease.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Database;

final class MigrationLock {
	public const OPTION         = 'cwf_migration_lock';
	private const LEASE_SECONDS = 1800;

	private ?string $owned_value = null;

	public function acquire(): bool {
		global $wpdb;

		$owner     = bin2hex( random_bytes( 16 ) );
		$candidate = wp_json_encode(
			array(
				'owner'       => $owner,
				'acquired_at' => time(),
			)
		);
		if ( ! is_string( $candidate ) ) {
			return false;
		}

		$inserted = $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO `{$wpdb->options}` (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				self::OPTION,
				$candidate
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery

		$this->invalidate_cache();
		if ( 1 === $inserted ) {
			$this->owned_value = $candidate;
			return true;
		}

		$observed = $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM `{$wpdb->options}` WHERE option_name = %s", self::OPTION )
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching

		if ( ! is_string( $observed ) || ! $this->is_stale( $observed ) ) {
			return false;
		}

		$replaced = $wpdb->query(
			$wpdb->prepare(
				"UPDATE `{$wpdb->options}` SET option_value = %s WHERE option_name = %s AND option_value = %s",
				$candidate,
				self::OPTION,
				$observed
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery

		$this->invalidate_cache();
		if ( 1 !== $replaced ) {
			return false;
		}

		$confirmed = $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM `{$wpdb->options}` WHERE option_name = %s", self::OPTION )
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching

		if ( $candidate !== $confirmed ) {
			return false;
		}

		$this->owned_value = $candidate;
		return true;
	}

	public function release(): void {
		global $wpdb;

		if ( null === $this->owned_value ) {
			return;
		}

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM `{$wpdb->options}` WHERE option_name = %s AND option_value = %s",
				self::OPTION,
				$this->owned_value
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery

		$this->owned_value = null;
		$this->invalidate_cache();
	}

	public function owns_lock(): bool {
		global $wpdb;

		if ( null === $this->owned_value ) {
			return false;
		}

		$current = $wpdb->get_var(
			$wpdb->prepare( "SELECT option_value FROM `{$wpdb->options}` WHERE option_name = %s", self::OPTION )
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching

		return $this->owned_value === $current;
	}

	private function is_stale( string $value ): bool {
		$decoded = json_decode( $value, true );
		return is_array( $decoded )
			&& isset( $decoded['acquired_at'] )
			&& is_int( $decoded['acquired_at'] )
			&& $decoded['acquired_at'] <= time() - self::LEASE_SECONDS;
	}

	private function invalidate_cache(): void {
		wp_cache_delete( self::OPTION, 'options' );
		wp_cache_delete( 'alloptions', 'options' );
	}
}
