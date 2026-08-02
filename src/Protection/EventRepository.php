<?php
/**
 * Atomic bounded decision-event aggregation.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Database\TableNames;
use Codeprint\CheckoutFirewall\Decision\DecisionResult;
use Codeprint\CheckoutFirewall\Decision\ReasonCatalog;
use Codeprint\CheckoutFirewall\Decision\ReasonCode;

final class EventRepository {
	private const BUCKET_SECONDS          = 3600;
	private const RECIPE_VERSION          = 2;
	private const OBSERVED_RECIPE_VERSION = 3;
	private string $table;
	private EventRetentionState $retention;

	public function __construct( ?TableNames $tables = null, ?EventRetentionState $retention = null ) {
		$this->table     = ( $tables ?? TableNames::from_wordpress() )->get( 'events' );
		$this->retention = $retention ?? new EventRetentionState();
	}

	/**
	 * Aggregate one non-default decision into its hourly event row.
	 *
	 * @param array<int,array<string,mixed>> $identities Request identities.
	 * @return bool Whether an event row was written.
	 * @throws \RuntimeException When persistence fails.
	 */
	public function record( DecisionResult $result, CheckoutContext $context, array $identities, ?int $now = null, bool $observed = false ): bool {
		global $wpdb;
		if ( ReasonCode::CHECKOUT_ALLOWED === $result->reason() || array() === $identities ) {
			return false;
		}
		$identity = $this->select_identity( $result->reason(), $identities );
		if ( null === $identity ) {
			return false;
		}
		$now                  = $now ?? time();
		$bucket               = $now - ( $now % self::BUCKET_SECONDS );
		$gateway              = substr( sanitize_key( $context->gateway_id() ), 0, 64 );
		$hint                 = isset( $identity['display_hint'] ) && is_string( $identity['display_hint'] ) ? substr( $identity['display_hint'], 0, 191 ) : null;
		$retention            = $observed ? 0 : $this->retention->days();
		$recipe               = $observed ? self::OBSERVED_RECIPE_VERSION : self::RECIPE_VERSION;
		$metadata             = $observed ? '{"observed_only":true}' : null;
		$metadata_placeholder = $observed ? '%s' : 'NULL';
		$material             = pack( 'n', $recipe ) . pack( 'n', $retention ) . "\0" . $result->reason() . "\0" . $result->action() . "\0" . $identity['identifier_hash'] . "\0" . $gateway . "\0" . (string) $bucket;
		$event_key            = hash_hmac( 'sha256', $material, (string) $identity['identifier_hash'], true );
		$arguments            = array(
			$event_key,
			$recipe,
			$retention,
			(int) $identity['key_version'],
			$identity['key_fingerprint'],
			$result->reason(),
			$result->action(),
			(int) $identity['identifier_type'],
			$identity['identifier_hash'],
			$hint,
			$gateway,
			gmdate( 'Y-m-d H:i:s', $bucket ),
			self::BUCKET_SECONDS,
			gmdate( 'Y-m-d H:i:s', $now ),
			gmdate( 'Y-m-d H:i:s', $now ),
		);
		if ( $observed ) {
			$arguments[] = $metadata;
		}
		// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- Recipe-specific metadata adds one value and placeholder together.
		$sql = $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table identifier; values use placeholders.
			"INSERT INTO `{$this->table}` (event_key,recipe_version,retention_days,key_version,key_fingerprint,reason_code,action,identifier_type,identifier_hash,display_hint,gateway_id,bucket_start_gmt,bucket_seconds,event_count,first_seen_gmt,last_seen_gmt,metadata) VALUES (%s,%d,%d,%d,%s,%s,%s,%d,%s,%s,%s,%s,%d,1,%s,%s,{$metadata_placeholder}) ON DUPLICATE KEY UPDATE event_count = event_count + 1, last_seen_gmt = GREATEST(last_seen_gmt, VALUES(last_seen_gmt)), display_hint = COALESCE(display_hint, VALUES(display_hint))",
			...$arguments
		);
		if ( false === $wpdb->query( $sql ) ) { // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			throw new \RuntimeException( 'Checkout Firewall event aggregation failed.' );
		}
		return true;
	}

	/**
	 * Read one bounded newest-first activity page.
	 *
	 * @return list<array<string,mixed>>
	 * @throws \RuntimeException When the bounded read fails.
	 */
	public function page( ?string $before_time = null, ?int $before_id = null, int $limit = 51 ): array {
		global $wpdb;
		$limit = max( 1, min( 51, $limit ) );
		$where = ' WHERE retention_days <> 90 AND last_seen_gmt >= %s';
		$args  = array( gmdate( 'Y-m-d H:i:s', time() - \Codeprint\CheckoutFirewall\Operations\RetentionPolicy::event_seconds() ) );
		if ( null !== $before_time && null !== $before_id && self::valid_date( $before_time ) && $before_id > 0 ) {
			$where .= ' AND (last_seen_gmt < %s OR (last_seen_gmt = %s AND id < %d))';
			array_push( $args, $before_time, $before_time, $before_id );
		}
		$args[] = $limit;
		$sql    = "SELECT id,recipe_version,reason_code,action,identifier_type,display_hint,gateway_id,event_count,first_seen_gmt,last_seen_gmt,metadata FROM `{$this->table}`{$where} ORDER BY last_seen_gmt DESC,id DESC LIMIT %d";
		$rows   = $wpdb->get_results( $wpdb->prepare( $sql, ...$args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded indexed operational page.
		if ( ! is_array( $rows ) || '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'Checkout Firewall event page read failed.' );
		}
		foreach ( $rows as &$row ) {
			$row['observed_only'] = self::OBSERVED_RECIPE_VERSION === (int) ( $row['recipe_version'] ?? 0 ) && '{"observed_only":true}' === ( $row['metadata'] ?? null );
			unset( $row['metadata'] );
		}
		unset( $row );
		return $rows;
	}

	/**
	 * Summarize a bounded newest-first set of retained intervention rows.
	 *
	 * Successful checkouts are intentionally absent from the event table. The
	 * truncation flag prevents the administration UI from presenting a partial
	 * sample as a complete retained-history total.
	 *
	 * @return array{challenges:int,blocks:int,would_challenge:int,would_block:int,identities:int,rows:int,truncated:bool}
	 * @throws \RuntimeException When the bounded read fails.
	 */
	public function summary( int $limit = 1000 ): array {
		global $wpdb;
		$limit = max( 1, min( 1000, $limit ) );
		$sql   = "SELECT recipe_version,action,identifier_type,identifier_hash,event_count,metadata FROM `{$this->table}` WHERE retention_days <> 90 AND last_seen_gmt >= %s ORDER BY last_seen_gmt DESC,id DESC LIMIT %d";
		$rows  = $wpdb->get_results( $wpdb->prepare( $sql, gmdate( 'Y-m-d H:i:s', time() - \Codeprint\CheckoutFirewall\Operations\RetentionPolicy::event_seconds() ), $limit + 1 ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded indexed operational summary.
		if ( ! is_array( $rows ) || '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'Checkout Firewall event summary read failed.' );
		}
		$truncated       = count( $rows ) > $limit;
		$rows            = array_slice( $rows, 0, $limit );
		$challenges      = 0;
		$blocks          = 0;
		$would_challenge = 0;
		$would_block     = 0;
		$identities      = array();
		foreach ( $rows as $row ) {
			$count    = max( 0, (int) ( $row['event_count'] ?? 0 ) );
			$observed = self::OBSERVED_RECIPE_VERSION === (int) ( $row['recipe_version'] ?? 0 ) && '{"observed_only":true}' === ( $row['metadata'] ?? null );
			if ( $observed && 'challenge' === ( $row['action'] ?? null ) ) {
				$would_challenge += $count;
			} elseif ( $observed && 'block' === ( $row['action'] ?? null ) ) {
				$would_block += $count;
			} elseif ( 'challenge' === ( $row['action'] ?? null ) ) {
				$challenges += $count;
			} elseif ( 'block' === ( $row['action'] ?? null ) ) {
				$blocks += $count;
			}
			if ( isset( $row['identifier_hash'] ) && is_string( $row['identifier_hash'] ) ) {
				$identities[ (int) ( $row['identifier_type'] ?? 0 ) . ':' . bin2hex( $row['identifier_hash'] ) ] = true;
			}
		}
		return array(
			'challenges'      => $challenges,
			'blocks'          => $blocks,
			'would_challenge' => $would_challenge,
			'would_block'     => $would_block,
			'identities'      => count( $identities ),
			'rows'            => count( $rows ),
			'truncated'       => $truncated,
		);
	}

	/**
	 * Select the identity appropriate for the emitted reason.
	 *
	 * @param array<int,array<string,mixed>> $identities Keyed identities.
	 * @return array<string,mixed>|null
	 */
	private function select_identity( string $reason, array $identities ): ?array {
		$types = array(
			ReasonCode::VELOCITY_COMBINED_EXCEEDED => IdentifierType::IP_EMAIL,
			ReasonCode::VELOCITY_SESSION_EXCEEDED  => IdentifierType::SESSION,
			ReasonCode::VELOCITY_EMAIL_EXCEEDED    => IdentifierType::EMAIL,
			ReasonCode::VELOCITY_IP_EXCEEDED       => IdentifierType::IP,
		);
		$type  = $types[ $reason ] ?? ( isset( $identities[ IdentifierType::SESSION ] ) ? IdentifierType::SESSION : IdentifierType::IP );
		return isset( $identities[ $type ] ) && is_array( $identities[ $type ] ) ? $identities[ $type ] : null;
	}

	private static function valid_date( string $value ): bool {
		return 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $value );
	}
}
