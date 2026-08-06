<?php
/**
 * Active and automatic local block persistence.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- The constructor accepts only the closed, prefix-validated TableNames registry; all data values are prepared.

use Codeprint\CheckoutFirewall\Database\TableNames;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;
use Codeprint\CheckoutFirewall\Operations\OperatingMode;

final class BlockRepository {
	private string $table;
	private OperatingMode $mode;

	public function __construct( ?TableNames $tables = null, ?OperatingMode $mode = null ) {
		$this->table = ( $tables ?? TableNames::from_wordpress() )->get( 'blocks' );
		$this->mode  = $mode ?? new OperatingMode();
	}

	/**
	 * Read the highest-priority active block matching a request identity.
	 *
	 * @param array<int,array<string,mixed>> $identities Keyed identities.
	 * @return array<string,mixed>|null
	 * @throws \RuntimeException When persistence fails.
	 */
	public function active( array $identities, ?int $now = null ): ?array {
		global $wpdb;
		$keys = array();
		foreach ( $identities as $identity ) {
			if ( isset( $identity['active_key'] ) && is_string( $identity['active_key'] ) ) {
				$keys[] = $identity['active_key'];
			}
		}
		if ( array() === $keys ) {
			return null;
		}
		$placeholders = implode( ',', array_fill( 0, count( $keys ), '%s' ) );
		// The placeholder count is generated from the already-bounded identity set.
		// phpcs:disable WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
		$sql = $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table and generated placeholders; values are prepared.
			"SELECT id,reason_code,source,active_key FROM `{$this->table}` WHERE active_key IN ({$placeholders}) AND status = 'active' AND expires_at_gmt > %s AND (reason_code = %s OR created_at_gmt >= %s) ORDER BY (reason_code = %s) DESC, id LIMIT 1",
			...array_merge( $keys, array( gmdate( 'Y-m-d H:i:s', $now ?? time() ), ReasonCode::EXPLICIT_LOCAL_BLOCK, $this->mode->enforcement_epoch(), ReasonCode::EXPLICIT_LOCAL_BLOCK ) )
		);
		// phpcs:enable WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
		$row = $wpdb->get_row( $sql, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( null === $row && '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'Checkout Firewall block read failed.' );
		}
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Create or extend an automatic failure block.
	 *
	 * @param array<string,mixed> $identity Keyed identity.
	 * @throws \InvalidArgumentException When the identity or source is invalid.
	 * @throws \RuntimeException When persistence fails.
	 */
	public function lock( array $identity, string $source, int $seconds, ?int $now = null ): void {
		global $wpdb;
		$now    = $now ?? time();
		$source = substr( sanitize_key( $source ), 0, 32 );
		$hint   = isset( $identity['display_hint'] ) && is_string( $identity['display_hint'] ) ? substr( $identity['display_hint'], 0, 191 ) : '';
		if ( '' === $source || ! isset( $identity['identifier_type'], $identity['key_version'], $identity['key_fingerprint'], $identity['identifier_hash'], $identity['active_key_version'], $identity['active_key_fingerprint'], $identity['active_key'] ) ) {
			throw new \InvalidArgumentException( 'Invalid automatic block identity.' );
		}
		$sql = $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table identifier; values use placeholders.
			"INSERT INTO `{$this->table}` (identifier_type,key_version,key_fingerprint,identifier_hash,active_key_version,active_key_fingerprint,active_key,display_hint,reason_code,source,status,created_at_gmt,expires_at_gmt,released_at_gmt) VALUES (%d,%d,%s,%s,%d,%s,%s,%s,%s,%s,'active',%s,%s,NULL) ON DUPLICATE KEY UPDATE reason_code = VALUES(reason_code), source = VALUES(source), status = 'active', expires_at_gmt = GREATEST(expires_at_gmt, VALUES(expires_at_gmt)), display_hint = IF(VALUES(display_hint) = '', display_hint, VALUES(display_hint)), released_at_gmt = NULL",
			(int) $identity['identifier_type'],
			(int) $identity['key_version'],
			$identity['key_fingerprint'],
			$identity['identifier_hash'],
			(int) $identity['active_key_version'],
			$identity['active_key_fingerprint'],
			$identity['active_key'],
			$hint,
			ReasonCode::PAYMENT_FAILURE_LOCKOUT,
			$source,
			gmdate( 'Y-m-d H:i:s', $now ),
			gmdate( 'Y-m-d H:i:s', $now + $seconds )
		);
		if ( false === $wpdb->query( $sql ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			throw new \RuntimeException( 'Checkout Firewall automatic block update failed.' );
		}
	}

	/**
	 * Create or upgrade one explicit local block.
	 *
	 * @param array<string,mixed> $identity Keyed current identity.
	 * @throws \InvalidArgumentException For incomplete identity material.
	 * @throws \RuntimeException When persistence fails.
	 */
	public function create_manual( array $identity, string $hint, ?int $seconds, ?int $now = null ): void {
		global $wpdb;
		$now = $now ?? time();
		if ( ! isset( $identity['identifier_type'], $identity['key_version'], $identity['key_fingerprint'], $identity['identifier_hash'], $identity['active_key_version'], $identity['active_key_fingerprint'], $identity['active_key'] ) ) {
			throw new \InvalidArgumentException( 'Invalid manual block identity.' );
		}
		$expires = null === $seconds ? '9999-12-31 23:59:59' : gmdate( 'Y-m-d H:i:s', $now + max( 1, $seconds ) );
		$sql     = $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table identifier; values use placeholders.
			"INSERT INTO `{$this->table}` (identifier_type,key_version,key_fingerprint,identifier_hash,active_key_version,active_key_fingerprint,active_key,display_hint,reason_code,source,status,created_at_gmt,expires_at_gmt,released_at_gmt) VALUES (%d,%d,%s,%s,%d,%s,%s,%s,%s,'manual','active',%s,%s,NULL) ON DUPLICATE KEY UPDATE identifier_type=VALUES(identifier_type),key_version=VALUES(key_version),key_fingerprint=VALUES(key_fingerprint),identifier_hash=VALUES(identifier_hash),display_hint=VALUES(display_hint),reason_code=VALUES(reason_code),source='manual',status='active',expires_at_gmt=GREATEST(expires_at_gmt,VALUES(expires_at_gmt)),released_at_gmt=NULL",
			(int) $identity['identifier_type'],
			(int) $identity['key_version'],
			$identity['key_fingerprint'],
			$identity['identifier_hash'],
			(int) $identity['active_key_version'],
			$identity['active_key_fingerprint'],
			$identity['active_key'],
			substr( $hint, 0, 191 ),
			ReasonCode::EXPLICIT_LOCAL_BLOCK,
			gmdate( 'Y-m-d H:i:s', $now ),
			$expires
		);
		if ( false === $wpdb->query( $sql ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			throw new \RuntimeException( 'Checkout Firewall manual block update failed.' );
		}
	}

	/**
	 * Read one bounded active-block page.
	 *
	 * @return list<array<string,mixed>>
	 * @throws \RuntimeException When the bounded read fails.
	 */
	public function page( ?string $after_expiry = null, ?int $after_id = null, int $limit = 51, ?int $now = null ): array {
		global $wpdb;
		$limit = max( 1, min( 51, $limit ) );
		$where = "status = 'active' AND expires_at_gmt > %s";
		$args  = array( gmdate( 'Y-m-d H:i:s', $now ?? time() ) );
		if ( null !== $after_expiry && null !== $after_id && self::valid_date( $after_expiry ) && $after_id > 0 ) {
			$where .= ' AND (expires_at_gmt > %s OR (expires_at_gmt = %s AND id > %d))';
			array_push( $args, $after_expiry, $after_expiry, $after_id );
		}
		$args[] = $limit;
		$sql    = "SELECT id,identifier_type,display_hint,reason_code,source,status,created_at_gmt,expires_at_gmt FROM `{$this->table}` WHERE {$where} ORDER BY expires_at_gmt,id LIMIT %d";
		$rows   = $wpdb->get_results( $wpdb->prepare( $sql, ...$args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded indexed operational page.
		if ( ! is_array( $rows ) || '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'Checkout Firewall block page read failed.' );
		}
		return $rows;
	}

	/**
	 * Read a small newest-first terminal block-history sample.
	 *
	 * @return list<array<string,mixed>>
	 * @throws \RuntimeException When the bounded read fails.
	 */
	public function history( int $limit = 10 ): array {
		global $wpdb;
		$limit = max( 1, min( 10, $limit ) );
		$sql   = "SELECT id,identifier_type,display_hint,reason_code,source,status,created_at_gmt,expires_at_gmt,released_at_gmt FROM `{$this->table}` WHERE status IN ('released','expired') ORDER BY COALESCE(released_at_gmt,expires_at_gmt) DESC,id DESC LIMIT %d";
		$rows  = $wpdb->get_results( $wpdb->prepare( $sql, $limit ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded operational history.
		if ( ! is_array( $rows ) || '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'Checkout Firewall block history read failed.' );
		}
		return $rows;
	}

	public function release_id( int $id, ?int $now = null ): bool {
		global $wpdb;
		if ( $id < 1 ) {
			return false;
		}
		$result = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table identifier; values use placeholders.
				"UPDATE `{$this->table}` SET status='released',active_key=NULL,released_at_gmt=%s WHERE id=%d AND status='active' AND expires_at_gmt>%s",
				gmdate( 'Y-m-d H:i:s', $now ?? time() ),
				$id,
				gmdate( 'Y-m-d H:i:s', $now ?? time() )
			)
		); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( false === $result ) {
			throw new \RuntimeException( 'Checkout Firewall block release failed.' );
		}
		return 1 === $result;
	}

	/**
	 * Release matching automatic blocks for request identities.
	 *
	 * @param array<int,array<string,mixed>> $identities Keyed identities.
	 * @throws \RuntimeException When persistence fails.
	 */
	public function release( array $identities, string $source, ?int $now = null ): void {
		global $wpdb;
		$keys = array();
		foreach ( $identities as $identity ) {
			if ( isset( $identity['active_key'] ) && is_string( $identity['active_key'] ) ) {
				$keys[] = $identity['active_key'];
			}
		}
		if ( array() === $keys ) {
			return;
		}
		$placeholders = implode( ',', array_fill( 0, count( $keys ), '%s' ) );
		// The placeholder count is generated from the already-bounded identity set.
		// phpcs:disable WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
		$sql = $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table and generated placeholders; values are prepared.
			"UPDATE `{$this->table}` SET status = 'released', active_key = NULL, released_at_gmt = %s WHERE active_key IN ({$placeholders}) AND status = 'active' AND reason_code = %s AND source = %s",
			...array_merge( array( gmdate( 'Y-m-d H:i:s', $now ?? time() ) ), $keys, array( ReasonCode::PAYMENT_FAILURE_LOCKOUT, substr( sanitize_key( $source ), 0, 32 ) ) )
		);
		// phpcs:enable WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber
		if ( false === $wpdb->query( $sql ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			throw new \RuntimeException( 'Checkout Firewall automatic block release failed.' );
		}
	}

	/**
	 * Release a bounded batch of automatic blocks from one gateway source.
	 *
	 * @throws \RuntimeException When persistence fails.
	 */
	public function release_source( string $source, ?int $now = null ): void {
		global $wpdb;
		$source = substr( sanitize_key( $source ), 0, 32 );
		if ( '' === $source ) {
			return;
		}
		$sql = $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table identifier; values use placeholders.
			"UPDATE `{$this->table}` SET status = 'released', active_key = NULL, released_at_gmt = %s WHERE status = 'active' AND reason_code = %s AND source = %s LIMIT 500",
			gmdate( 'Y-m-d H:i:s', $now ?? time() ),
			ReasonCode::PAYMENT_FAILURE_LOCKOUT,
			$source
		);
		if ( false === $wpdb->query( $sql ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			throw new \RuntimeException( 'Checkout Firewall gateway-source block release failed.' );
		}
	}

	private static function valid_date( string $value ): bool {
		return 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $value );
	}
}
