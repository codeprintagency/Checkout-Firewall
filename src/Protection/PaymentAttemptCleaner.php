<?php
/**
 * Bounded WooCommerce-order cleanup for temporary payment feedback snapshots.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Operations\RetentionPolicy;

final class PaymentAttemptCleaner {
	private const LIMIT = 250;

	/**
	 * Delete one bounded page of expired or legacy-stale snapshots.
	 *
	 * @return bool Whether another cleanup page may remain.
	 */
	public function expired(): bool {
		if ( ! function_exists( 'wc_get_orders' ) ) {
			return false;
		}

		$now     = gmdate( 'Y-m-d H:i:s' );
		$expired = $this->orders(
			array(
				'meta_query' => array(
					array(
						'key'     => PaymentFeedback::EXPIRY_META_KEY,
						'value'   => $now,
						'compare' => '<=',
						'type'    => 'DATETIME',
					),
				),
			)
		);
		$backlog = count( $expired ) > self::LIMIT;
		$this->delete_orders( array_slice( $expired, 0, self::LIMIT ) );

		if ( $backlog ) {
			return true;
		}

		$legacy = $this->orders(
			array(
				'date_modified' => '<' . ( time() - RetentionPolicy::event_seconds() ),
				'meta_query'    => array(
					'relation' => 'AND',
					array(
						'key'     => PaymentFeedback::META_KEY,
						'compare' => 'EXISTS',
					),
					array(
						'key'     => PaymentFeedback::EXPIRY_META_KEY,
						'compare' => 'NOT EXISTS',
					),
				),
			)
		);
		$this->delete_orders( array_slice( $legacy, 0, self::LIMIT ) );
		return count( $legacy ) > self::LIMIT;
	}

	/**
	 * Erase directly email-attributable snapshots under every retained key.
	 *
	 * @param list<array{key_version:int,key_fingerprint:string,identifier_hash:string}> $variants Retained-key hashes.
	 * @return array{removed:int,more:bool}
	 */
	public function erase_email( array $variants, int $limit ): array {
		$limit = max( 0, min( self::LIMIT, $limit ) );
		if ( ! function_exists( 'wc_get_orders' ) ) {
			return array(
				'removed' => 0,
				'more'    => false,
			);
		}
		if ( 0 === $limit ) {
			return array(
				'removed' => 0,
				'more'    => array() !== $this->email_orders( $variants, 1 ),
			);
		}

		$matched = array();
		foreach ( $this->email_orders( $variants, $limit + 1 ) as $order_id ) {
			$order = wc_get_order( $order_id );
			if ( $order instanceof \WC_Order && $this->matches_email( $order, $variants ) ) {
				$matched[] = $order;
			}
		}

		$removed = 0;
		foreach ( array_slice( $matched, 0, $limit ) as $order ) {
			self::delete( $order );
			++$removed;
		}

		return array(
			'removed' => $removed,
			'more'    => count( $matched ) > $limit,
		);
	}

	/**
	 * Remove all plugin-owned payment snapshots during an authorized uninstall.
	 */
	public function purge_all(): void {
		$this->purge_storage_tables();
	}

	/**
	 * Query a bounded list of order IDs using WooCommerce's active data store.
	 *
	 * @param array<string,mixed> $arguments Additional order-query arguments.
	 * @return list<int>
	 */
	private function orders( array $arguments ): array {
		$defaults  = array(
			'limit'   => self::LIMIT + 1,
			'return'  => 'ids',
			'orderby' => 'ID',
			'order'   => 'ASC',
			'status'  => array_keys( wc_get_order_statuses() ),
		);
		$arguments = array_merge( $defaults, $arguments );
		if ( ! self::uses_hpos() ) {
			return $this->legacy_orders( $arguments );
		}
		$orders = wc_get_orders( $arguments );
		return array_values( array_filter( array_map( 'intval', $orders ) ) );
	}

	/**
	 * Query order IDs through WordPress when the legacy posts data store is active.
	 *
	 * @param array<string,mixed> $arguments Normalized order-query arguments.
	 * @return list<int>
	 */
	private function legacy_orders( array $arguments ): array {
		$query = array(
			'post_type'              => wc_get_order_types( 'view-orders' ),
			'post_status'            => $arguments['status'],
			'posts_per_page'         => (int) $arguments['limit'],
			'fields'                 => 'ids',
			'orderby'                => 'ID',
			'order'                  => 'ASC',
			'no_found_rows'          => true,
			'update_post_meta_cache' => false,
			'update_post_term_cache' => false,
		);
		if ( isset( $arguments['meta_query'] ) && is_array( $arguments['meta_query'] ) ) {
			$query['meta_query'] = $arguments['meta_query'];
		}
		if ( isset( $arguments['date_modified'] ) && is_string( $arguments['date_modified'] ) ) {
			$query['date_query'] = array(
				array(
					'column'    => 'post_modified_gmt',
					'before'    => gmdate( 'Y-m-d H:i:s', (int) ltrim( $arguments['date_modified'], '<' ) ),
					'inclusive' => false,
				),
			);
		}
		$orders = ( new \WP_Query( $query ) )->posts;
		return array_values( array_filter( array_map( 'intval', $orders ) ) );
	}

	private static function uses_hpos(): bool {
		return class_exists( '\\Automattic\\WooCommerce\\Utilities\\OrderUtil' )
			&& \Automattic\WooCommerce\Utilities\OrderUtil::custom_orders_table_usage_is_enabled();
	}

	/**
	 * Query order snapshots containing any retained direct-email hash.
	 *
	 * @param list<array{key_version:int,key_fingerprint:string,identifier_hash:string}> $variants Retained-key hashes.
	 * @return list<int>
	 */
	private function email_orders( array $variants, int $limit ): array {
		$meta_query = array( 'relation' => 'OR' );
		foreach ( array_slice( $variants, 0, 32 ) as $variant ) {
			$meta_query[] = array(
				'key'     => PaymentFeedback::META_KEY,
				'value'   => bin2hex( $variant['identifier_hash'] ),
				'compare' => 'LIKE',
			);
		}
		if ( 1 === count( $meta_query ) ) {
			return array();
		}
		return $this->orders(
			array(
				'limit'      => $limit,
				'meta_query' => $meta_query,
			)
		);
	}

	/**
	 * Confirm a query match against the structured direct-email identity row.
	 *
	 * @param list<array{key_version:int,key_fingerprint:string,identifier_hash:string}> $variants Retained-key hashes.
	 */
	private function matches_email( \WC_Order $order, array $variants ): bool {
		$attempt = $order->get_meta( PaymentFeedback::META_KEY, true );
		$row     = is_array( $attempt ) && is_array( $attempt['identities'] ?? null ) ? ( $attempt['identities'][ IdentifierType::EMAIL ] ?? null ) : null;
		if ( ! is_array( $row ) || ! is_string( $row['identifier_hash'] ?? null ) ) {
			return false;
		}
		foreach ( $variants as $variant ) {
			if ( (int) ( $row['key_version'] ?? 0 ) === $variant['key_version'] && hash_equals( bin2hex( $variant['identifier_hash'] ), $row['identifier_hash'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Delete payment snapshots from the selected orders.
	 *
	 * @param list<int> $order_ids Order IDs.
	 */
	private function delete_orders( array $order_ids ): void {
		foreach ( $order_ids as $order_id ) {
			$order = wc_get_order( $order_id );
			if ( $order instanceof \WC_Order ) {
				self::delete( $order );
			}
		}
	}

	private static function delete( \WC_Order $order ): void {
		$order->delete_meta_data( PaymentFeedback::META_KEY );
		$order->delete_meta_data( PaymentFeedback::EXPIRY_META_KEY );
		$order->save_meta_data();
	}

	/**
	 * Remove inactive-data-store copies and support uninstall after WooCommerce is disabled.
	 */
	private function purge_storage_tables(): void {
		global $wpdb;
		$tables = array( $wpdb->postmeta, $wpdb->prefix . 'wc_orders_meta' );
		foreach ( $tables as $table ) {
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Exact uninstall storage probe.
			if ( $table !== $found ) {
				continue;
			}
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM `{$table}` WHERE meta_key IN (%s,%s)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Exact verified WooCommerce metadata table.
					PaymentFeedback::META_KEY,
					PaymentFeedback::EXPIRY_META_KEY
				)
			); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit destructive uninstall.
		}
	}
}
