<?php
/**
 * Bounded retention cleanup.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Database;

use Codeprint\CheckoutFirewall\Support\Health;
use Codeprint\CheckoutFirewall\Operations\RetentionPolicy;

// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Identifiers come exclusively from TableNames and private allowlisted column arguments; all values remain prepared.
final class Cleaner {
	private const BATCH_SIZE          = 500;
	private const ROW_LIMIT           = 5000;
	private const WALL_LIMIT_SECONDS  = 5.0;
	private const QUERY_LIMIT_SECONDS = 0.2;

	private TableNames $tables;
	private float $started_at  = 0.0;
	private float $query_time  = 0.0;
	private int $affected_rows = 0;

	public function __construct( ?TableNames $tables = null ) {
		$this->tables = $tables ?? TableNames::from_wordpress();
	}

	public function events(): bool {
		$this->reset_budget();
		$table   = $this->tables->get( 'events' );
		$backlog = $this->delete_events_by_class( $table, 90, gmdate( 'Y-m-d H:i:s', time() - ( 90 * DAY_IN_SECONDS ) ), 2500 );
		if ( ! $this->budget_exhausted() ) {
			$backlog = $this->delete_events_by_class( $table, 0, gmdate( 'Y-m-d H:i:s', time() - RetentionPolicy::event_seconds() ), 2000 ) || $backlog;
		}
		if ( ! $this->budget_exhausted() ) {
			$backlog = $this->delete_unknown_event_classes( $table, gmdate( 'Y-m-d H:i:s', time() - RetentionPolicy::event_seconds() ) ) || $backlog;
		}
		return $backlog || $this->budget_exhausted();
	}

	private function delete_events_by_class( string $table, int $retention_days, string $cutoff, int $class_limit ): bool {
		global $wpdb;
		$last_batch_full = false;
		$class_started   = $this->affected_rows;
		while ( ! $this->budget_exhausted() && $this->affected_rows - $class_started < $class_limit ) {
			$limit = min( self::BATCH_SIZE, self::ROW_LIMIT - $this->affected_rows, $class_limit - ( $this->affected_rows - $class_started ) );
			if ( $limit < 1 ) {
				return true;
			}
			$ids = $this->timed_get_col( $wpdb->prepare( "SELECT id FROM `{$table}` WHERE retention_days = %d AND last_seen_gmt < %s ORDER BY last_seen_gmt,id LIMIT %d", $retention_days, $cutoff, $limit ) );
			if ( array() === $ids ) {
				return false;
			}
			$this->delete_ids( $table, $ids );
			$last_batch_full = count( $ids ) === $limit;
			if ( ! $last_batch_full ) {
				return false;
			}
		}
		return $last_batch_full || $this->affected_rows - $class_started >= $class_limit;
	}

	private function delete_unknown_event_classes( string $table, string $cutoff ): bool {
		global $wpdb;
		$limit = min( self::BATCH_SIZE, self::ROW_LIMIT - $this->affected_rows );
		if ( $limit < 1 ) {
			return true;
		}
		$ids = $this->timed_get_col( $wpdb->prepare( "SELECT id FROM `{$table}` WHERE retention_days NOT IN (0,90) AND last_seen_gmt < %s ORDER BY last_seen_gmt,id LIMIT %d", $cutoff, $limit ) );
		if ( array() === $ids ) {
			return false;
		}
		$this->delete_ids( $table, $ids );
		return count( $ids ) === $limit;
	}

	public function counters(): bool {
		$this->reset_budget();
		return $this->delete_before( $this->tables->get( 'counters' ), 'expires_at_gmt', gmdate( 'Y-m-d H:i:s' ) );
	}

	public function consumed_tokens(): bool {
		$this->reset_budget();
		return $this->delete_before( $this->tables->get( 'consumed_tokens' ), 'expires_at_gmt', gmdate( 'Y-m-d H:i:s' ) );
	}

	public function blocks(): bool {
		$this->reset_budget();
		$table   = $this->tables->get( 'blocks' );
		$now     = gmdate( 'Y-m-d H:i:s' );
		$history = gmdate( 'Y-m-d H:i:s', time() - RetentionPolicy::history_seconds() );
		$backlog = $this->expire_active_blocks( $table, $now );

		if ( ! $this->budget_exhausted() ) {
			$backlog = $this->age_hints_by_primary_key( $table ) || $backlog;
		}

		if ( ! $this->budget_exhausted() ) {
			$backlog = $this->delete_terminal_blocks( $table, 'released', 'released_at_gmt', $history ) || $backlog;
		}

		if ( ! $this->budget_exhausted() ) {
			$backlog = $this->delete_terminal_blocks( $table, 'expired', 'expires_at_gmt', $history ) || $backlog;
		}

		return $backlog || $this->budget_exhausted();
	}

	private function delete_before( string $table, string $column, string $cutoff ): bool {
		global $wpdb;

		$last_batch_full = false;
		while ( ! $this->budget_exhausted() ) {
			$limit = min( self::BATCH_SIZE, self::ROW_LIMIT - $this->affected_rows );
			if ( $limit < 1 ) {
				return true;
			}

			$ids = $this->timed_get_col(
				$wpdb->prepare(
					"SELECT id FROM `{$table}` WHERE `{$column}` < %s ORDER BY `{$column}`, id LIMIT %d",
					$cutoff,
					$limit
				)
			); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

			if ( array() === $ids ) {
				return false;
			}

			$this->delete_ids( $table, $ids );
			$last_batch_full = count( $ids ) === $limit;
			if ( ! $last_batch_full ) {
				return false;
			}
		}

		return $last_batch_full;
	}

	private function expire_active_blocks( string $table, string $now ): bool {
		global $wpdb;

		$ids = $this->timed_get_col(
			$wpdb->prepare(
				"SELECT id FROM `{$table}` WHERE status = 'active' AND expires_at_gmt < %s ORDER BY expires_at_gmt, id LIMIT %d",
				$now,
				self::BATCH_SIZE
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( array() === $ids ) {
			return false;
		}

		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$sql          = $wpdb->prepare(
			"UPDATE `{$table}` SET status = 'expired', active_key = NULL WHERE status = 'active' AND id IN ({$placeholders})",
			...array_map( 'intval', $ids )
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$this->timed_query( $sql );
		return count( $ids ) === self::BATCH_SIZE;
	}

	private function age_hints_by_primary_key( string $table ): bool {
		global $wpdb;

		$cursor = Health::timestamp( 'blocks_hint_cursor' );
		$rows   = $this->timed_get_results(
			$wpdb->prepare(
				"SELECT id, created_at_gmt, display_hint FROM `{$table}` WHERE id > %d ORDER BY id LIMIT %d",
				$cursor,
				self::BATCH_SIZE
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( array() === $rows ) {
			Health::set_timestamp( 'blocks_hint_cursor', 0 );
			return false;
		}

		$cutoff = time() - RetentionPolicy::hint_seconds();
		$ids    = array();
		foreach ( $rows as $row ) {
			if ( null !== ( $row['display_hint'] ?? null ) && strtotime( (string) ( $row['created_at_gmt'] ?? '' ) . ' UTC' ) <= $cutoff ) {
				$ids[] = (int) $row['id'];
			}
		}

		if ( array() !== $ids ) {
			$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
			$sql          = $wpdb->prepare(
				"UPDATE `{$table}` SET display_hint = NULL WHERE id IN ({$placeholders})",
				...$ids
			); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$this->timed_query( $sql );
		}

		$last_id = (int) $rows[ count( $rows ) - 1 ]['id'];
		Health::set_timestamp( 'blocks_hint_cursor', count( $rows ) === self::BATCH_SIZE ? $last_id : 0 );
		return count( $rows ) === self::BATCH_SIZE;
	}

	private function delete_terminal_blocks( string $table, string $status, string $column, string $cutoff ): bool {
		global $wpdb;

		$ids = $this->timed_get_col(
			$wpdb->prepare(
				"SELECT id FROM `{$table}` WHERE status = %s AND `{$column}` < %s ORDER BY `{$column}`, id LIMIT %d",
				$status,
				$cutoff,
				self::BATCH_SIZE
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( array() === $ids ) {
			return false;
		}

		$this->delete_ids( $table, $ids );
		return count( $ids ) === self::BATCH_SIZE;
	}

	/**
	 * Delete a prepared list of numeric row IDs.
	 *
	 * @param list<int|string> $ids Row identifiers.
	 */
	private function delete_ids( string $table, array $ids ): void {
		global $wpdb;

		$ids                  = array_map( 'intval', $ids );
		$placeholders         = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$sql                  = $wpdb->prepare( "DELETE FROM `{$table}` WHERE id IN ({$placeholders})", ...$ids ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$affected             = $this->timed_query( $sql );
		$this->affected_rows += max( 0, $affected );
	}

	/**
	 * Run a timed column query.
	 *
	 * @return list<int|string>
	 * @throws \RuntimeException When the query fails.
	 */
	private function timed_get_col( string $sql ): array {
		global $wpdb;

		$started         = microtime( true );
		$previous_errors = $wpdb->suppress_errors( true );
		try {
			$result = $wpdb->get_col( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		} finally {
			$wpdb->suppress_errors( $previous_errors );
		}
		$this->query_time += microtime( true ) - $started;
		if ( ! is_array( $result ) || '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'Checkout Firewall cleanup selection failed.' );
		}

		return $result;
	}

	/**
	 * Run a timed row query.
	 *
	 * @return list<array<string, mixed>>
	 * @throws \RuntimeException When the query fails.
	 */
	private function timed_get_results( string $sql ): array {
		global $wpdb;

		$started         = microtime( true );
		$previous_errors = $wpdb->suppress_errors( true );
		try {
			$result = $wpdb->get_results( $sql, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		} finally {
			$wpdb->suppress_errors( $previous_errors );
		}
		$this->query_time += microtime( true ) - $started;
		if ( ! is_array( $result ) || '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'Checkout Firewall cleanup scan failed.' );
		}

		return $result;
	}

	private function timed_query( string $sql ): int {
		global $wpdb;

		$started         = microtime( true );
		$previous_errors = $wpdb->suppress_errors( true );
		try {
			$result = $wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery
		} finally {
			$wpdb->suppress_errors( $previous_errors );
		}
		$this->query_time += microtime( true ) - $started;
		if ( false === $result ) {
			throw new \RuntimeException( 'Checkout Firewall cleanup mutation failed.' );
		}

		return (int) $result;
	}

	private function reset_budget(): void {
		$this->started_at    = microtime( true );
		$this->query_time    = 0.0;
		$this->affected_rows = 0;
	}

	private function budget_exhausted(): bool {
		return $this->affected_rows >= self::ROW_LIMIT
			|| microtime( true ) - $this->started_at >= self::WALL_LIMIT_SECONDS
			|| $this->query_time >= self::QUERY_LIMIT_SECONDS;
	}
}
// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
