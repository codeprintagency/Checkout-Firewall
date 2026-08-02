<?php
/**
 * Schema v2 definitions and verification contract.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Database;

final class Schema {
	public const VERSION = 2;

	private TableNames $tables;

	public function __construct( TableNames $tables ) {
		$this->tables = $tables;
	}

	/**
	 * Build the complete dbDelta schema definitions.
	 *
	 * @return array<string, string>
	 */
	public function definitions(): array {
		global $wpdb;

		$tables                = $this->tables->all();
		$charset_collate       = $wpdb->get_charset_collate();
		$definitions           = array();
		$definitions['events'] = "CREATE TABLE {$tables['events']} (
id bigint(20) unsigned NOT NULL auto_increment,
event_key binary(32) NOT NULL,
recipe_version smallint(5) unsigned NOT NULL,
retention_days smallint(5) unsigned NOT NULL DEFAULT 0,
key_version smallint(5) unsigned NOT NULL,
key_fingerprint binary(8) NOT NULL,
reason_code varchar(64) NOT NULL,
action varchar(16) NOT NULL,
identifier_type smallint(5) unsigned NOT NULL,
identifier_hash binary(32) NOT NULL,
display_hint varchar(191) DEFAULT NULL,
gateway_id varchar(64) NOT NULL DEFAULT '',
bucket_start_gmt datetime NOT NULL,
bucket_seconds int(10) unsigned NOT NULL,
event_count bigint(20) unsigned NOT NULL DEFAULT 1,
first_seen_gmt datetime NOT NULL,
last_seen_gmt datetime NOT NULL,
metadata text NULL,
PRIMARY KEY  (id),
UNIQUE KEY event_key (event_key),
KEY bucket_start_gmt (bucket_start_gmt),
KEY last_seen_gmt (last_seen_gmt),
KEY retention_last_seen (retention_days,last_seen_gmt),
KEY reason_last_seen (reason_code,last_seen_gmt),
KEY identifier_last_seen (identifier_type,key_version,identifier_hash,last_seen_gmt)
) ENGINE=InnoDB {$charset_collate};";

		$definitions['counters'] = "CREATE TABLE {$tables['counters']} (
id bigint(20) unsigned NOT NULL auto_increment,
counter_type smallint(5) unsigned NOT NULL,
key_version smallint(5) unsigned NOT NULL,
key_fingerprint binary(8) NOT NULL,
identifier_hash binary(32) NOT NULL,
gateway_id varchar(64) NOT NULL DEFAULT '',
window_start_gmt datetime NOT NULL,
window_seconds int(10) unsigned NOT NULL,
counter_value bigint(20) unsigned NOT NULL DEFAULT 0,
expires_at_gmt datetime NOT NULL,
updated_at_gmt datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY counter_bucket (counter_type,key_version,identifier_hash,gateway_id,window_start_gmt,window_seconds),
KEY expires_at_gmt (expires_at_gmt)
) ENGINE=InnoDB {$charset_collate};";

		$definitions['blocks'] = "CREATE TABLE {$tables['blocks']} (
id bigint(20) unsigned NOT NULL auto_increment,
identifier_type smallint(5) unsigned NOT NULL,
key_version smallint(5) unsigned NOT NULL,
key_fingerprint binary(8) NOT NULL,
identifier_hash binary(32) NOT NULL,
active_key_version smallint(5) unsigned NOT NULL,
active_key_fingerprint binary(8) NOT NULL,
active_key binary(32) DEFAULT NULL,
display_hint varchar(191) DEFAULT NULL,
reason_code varchar(64) NOT NULL,
source varchar(32) NOT NULL,
status varchar(16) NOT NULL DEFAULT 'active',
created_at_gmt datetime NOT NULL,
expires_at_gmt datetime NOT NULL,
released_at_gmt datetime DEFAULT NULL,
PRIMARY KEY  (id),
UNIQUE KEY active_key (active_key),
KEY active_match (identifier_type,key_version,identifier_hash,status,expires_at_gmt),
KEY status_expiry (status,expires_at_gmt),
KEY status_release (status,released_at_gmt)
) ENGINE=InnoDB {$charset_collate};";

		$definitions['consumed_tokens'] = "CREATE TABLE {$tables['consumed_tokens']} (
id bigint(20) unsigned NOT NULL auto_increment,
token_hash binary(32) NOT NULL,
context_hash binary(32) NOT NULL,
key_version smallint(5) unsigned NOT NULL,
key_fingerprint binary(8) NOT NULL,
consumed_at_gmt datetime NOT NULL,
expires_at_gmt datetime NOT NULL,
PRIMARY KEY  (id),
UNIQUE KEY token_hash (token_hash),
KEY expires_at_gmt (expires_at_gmt)
) ENGINE=InnoDB {$charset_collate};";

		return $definitions;
	}

	/**
	 * Return required columns by table.
	 *
	 * @return array<string, list<string>>
	 */
	public function expected_columns(): array {
		return array(
			'events'          => array( 'id', 'event_key', 'recipe_version', 'retention_days', 'key_version', 'key_fingerprint', 'reason_code', 'action', 'identifier_type', 'identifier_hash', 'display_hint', 'gateway_id', 'bucket_start_gmt', 'bucket_seconds', 'event_count', 'first_seen_gmt', 'last_seen_gmt', 'metadata' ),
			'counters'        => array( 'id', 'counter_type', 'key_version', 'key_fingerprint', 'identifier_hash', 'gateway_id', 'window_start_gmt', 'window_seconds', 'counter_value', 'expires_at_gmt', 'updated_at_gmt' ),
			'blocks'          => array( 'id', 'identifier_type', 'key_version', 'key_fingerprint', 'identifier_hash', 'active_key_version', 'active_key_fingerprint', 'active_key', 'display_hint', 'reason_code', 'source', 'status', 'created_at_gmt', 'expires_at_gmt', 'released_at_gmt' ),
			'consumed_tokens' => array( 'id', 'token_hash', 'context_hash', 'key_version', 'key_fingerprint', 'consumed_at_gmt', 'expires_at_gmt' ),
		);
	}

	/**
	 * Return required indexes by table.
	 *
	 * @return array<string, list<string>>
	 */
	public function expected_indexes(): array {
		return array(
			'events'          => array( 'PRIMARY', 'event_key', 'bucket_start_gmt', 'last_seen_gmt', 'retention_last_seen', 'reason_last_seen', 'identifier_last_seen' ),
			'counters'        => array( 'PRIMARY', 'counter_bucket', 'expires_at_gmt' ),
			'blocks'          => array( 'PRIMARY', 'active_key', 'active_match', 'status_expiry', 'status_release' ),
			'consumed_tokens' => array( 'PRIMARY', 'token_hash', 'expires_at_gmt' ),
		);
	}

	/**
	 * Verify tables, columns, indexes, engine, and collation.
	 *
	 * @return list<string>
	 */
	public function verify(): array {
		global $wpdb;

		$issues             = array();
		$expected_columns   = $this->expected_columns();
		$expected_indexes   = $this->expected_indexes();
		$expected_collation = strtolower( (string) $wpdb->collate );

		foreach ( $this->tables->all() as $logical_name => $table ) {
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			if ( $table !== $found ) {
				$issues[] = $logical_name . '_table_missing';
				continue;
			}

			$columns = $wpdb->get_results( "SHOW COLUMNS FROM `{$table}`", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$names   = is_array( $columns ) ? array_column( $columns, 'Field' ) : array();
			foreach ( $expected_columns[ $logical_name ] as $column ) {
				if ( ! in_array( $column, $names, true ) ) {
					$issues[] = $logical_name . '_column_' . $column;
				}
			}

			$indexes     = $wpdb->get_results( "SHOW INDEX FROM `{$table}`", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$index_names = is_array( $indexes ) ? array_unique( array_column( $indexes, 'Key_name' ) ) : array();
			foreach ( $expected_indexes[ $logical_name ] as $index ) {
				if ( ! in_array( $index, $index_names, true ) ) {
					$issues[] = $logical_name . '_index_' . strtolower( $index );
				}
			}

			$status = $wpdb->get_row( $wpdb->prepare( 'SHOW TABLE STATUS LIKE %s', $wpdb->esc_like( $table ) ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			if ( ! is_array( $status ) || 'INNODB' !== strtoupper( (string) ( $status['Engine'] ?? '' ) ) ) {
				$issues[] = $logical_name . '_engine';
			}

			$actual_collation = strtolower( (string) ( $status['Collation'] ?? '' ) );
			if ( '' !== $expected_collation && $actual_collation !== $expected_collation ) {
				$issues[] = $logical_name . '_collation';
			}
		}

		return array_values( array_unique( $issues ) );
	}
}
