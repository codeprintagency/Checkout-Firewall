<?php
/**
 * Atomic M4 counter persistence.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- The table identifier is resolved from the closed, prefix-validated TableNames registry; all counter values are prepared.

use Codeprint\CheckoutFirewall\Data\CounterType;
use Codeprint\CheckoutFirewall\Database\TableNames;

final class CounterRepository {
	private string $table;

	public function __construct( ?TableNames $tables = null ) {
		$this->table = ( $tables ?? TableNames::from_wordpress() )->get( 'counters' );
	}

	/**
	 * Atomically increment one bucket for every supplied identity.
	 *
	 * @param array<int,array<string,mixed>> $identities Keyed identity rows.
	 * @throws \RuntimeException When persistence fails.
	 */
	public function increment( array $identities, int $counter_type, string $gateway = '', ?int $now = null ): void {
		global $wpdb;
		if ( ! CounterType::is_valid( $counter_type ) || array() === $identities ) {
			return;
		}
		$now          = $now ?? time();
		$bucket_start = $now - ( $now % ProtectionPolicy::BUCKET_SECONDS );
		$gateway      = substr( sanitize_key( $gateway ), 0, 64 );
		$values       = array();
		$arguments    = array();
		foreach ( $identities as $identity ) {
			if ( ! isset( $identity['key_version'], $identity['key_fingerprint'], $identity['identifier_hash'] ) ) {
				continue;
			}
			$values[] = '(%d,%d,%s,%s,%s,%s,%d,%d,%s,%s)';
			array_push(
				$arguments,
				$counter_type,
				(int) $identity['key_version'],
				$identity['key_fingerprint'],
				$identity['identifier_hash'],
				$gateway,
				gmdate( 'Y-m-d H:i:s', $bucket_start ),
				ProtectionPolicy::BUCKET_SECONDS,
				1,
				gmdate( 'Y-m-d H:i:s', $bucket_start + 1800 ),
				gmdate( 'Y-m-d H:i:s', $now )
			);
		}
		if ( array() === $values ) {
			return;
		}
		$sql    = "INSERT INTO `{$this->table}` (counter_type,key_version,key_fingerprint,identifier_hash,gateway_id,window_start_gmt,window_seconds,counter_value,expires_at_gmt,updated_at_gmt) VALUES " . implode( ',', $values ) . ' ON DUPLICATE KEY UPDATE counter_value = counter_value + 1, expires_at_gmt = GREATEST(expires_at_gmt, VALUES(expires_at_gmt)), updated_at_gmt = VALUES(updated_at_gmt)';
		$result = $wpdb->query( $wpdb->prepare( $sql, ...$arguments ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( false === $result ) {
			throw new \RuntimeException( 'Checkout Firewall counter update failed.' );
		}
	}

	/**
	 * Read rolling totals for each supplied identity.
	 *
	 * @param array<int,array<string,mixed>> $identities Keyed identity rows.
	 * @return array<int,int> Totals keyed by identifier type.
	 * @throws \RuntimeException When persistence fails.
	 */
	public function totals( array $identities, int $counter_type, int $window, string $gateway = '', ?int $now = null ): array {
		global $wpdb;
		$now     = $now ?? time();
		$gateway = substr( sanitize_key( $gateway ), 0, 64 );
		$totals  = array();
		foreach ( $identities as $type => $identity ) {
			if ( ! isset( $identity['key_version'], $identity['identifier_hash'] ) ) {
				continue;
			}
			$variants  = isset( $identity['retained_identifiers'] ) && is_array( $identity['retained_identifiers'] )
				? array_slice( $identity['retained_identifiers'], 0, 32 )
				: array( $identity );
			$pairs     = array();
			$arguments = array( $counter_type, $gateway, gmdate( 'Y-m-d H:i:s', $now - $window ), gmdate( 'Y-m-d H:i:s', $now ), ProtectionPolicy::BUCKET_SECONDS );
			foreach ( $variants as $variant ) {
				if ( ! is_array( $variant ) || ! isset( $variant['key_version'], $variant['identifier_hash'] ) ) {
					continue;
				}
				$pairs[]     = '(key_version = %d AND identifier_hash = %s)';
				$arguments[] = (int) $variant['key_version'];
				$arguments[] = $variant['identifier_hash'];
			}
			if ( array() === $pairs ) {
				continue;
			}
			$sql   = "SELECT COALESCE(SUM(counter_value),0) FROM `{$this->table}` USE INDEX (counter_bucket) WHERE counter_type = %d AND gateway_id = %s AND window_start_gmt >= %s AND window_start_gmt <= %s AND window_seconds = %d AND (" . implode( ' OR ', $pairs ) . ')';
			$value = $wpdb->get_var(
				$wpdb->prepare( $sql, ...$arguments ) // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Internal table and generated bounded placeholders; values are prepared.
			); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			if ( null === $value || '' !== $wpdb->last_error ) {
				throw new \RuntimeException( 'Checkout Firewall counter read failed.' );
			}
			$totals[ (int) $type ] = (int) $value;
		}
		return $totals;
	}
}
