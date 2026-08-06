<?php
/**
 * Bounded WordPress direct-email personal-data eraser.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Privacy;

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- Erasure table identifiers come only from the closed TableNames registry; hashes, types, limits, and row IDs are prepared and bounded.

use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Database\TableNames;
use Codeprint\CheckoutFirewall\Protection\PaymentAttemptCleaner;
use Codeprint\CheckoutFirewall\Security\KeyStore;
use Codeprint\CheckoutFirewall\Protection\TrustedExemptionStore;

final class PersonalDataEraser {
	private const LIMIT = 250;
	private KeyStore $keys;
	private TableNames $tables;
	private PaymentAttemptCleaner $payment_attempts;

	public function __construct( ?KeyStore $keys = null, ?TableNames $tables = null, ?PaymentAttemptCleaner $payment_attempts = null ) {
		$this->keys             = $keys ?? new KeyStore();
		$this->tables           = $tables ?? TableNames::from_wordpress();
		$this->payment_attempts = $payment_attempts ?? new PaymentAttemptCleaner();
	}

	public function register(): void {
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'erasers' ) );
	}

	/**
	 * Register the native eraser callback.
	 *
	 * @param array<string,mixed> $erasers Existing erasers.
	 * @return array<string,mixed>
	 */
	public function erasers( array $erasers ): array {
		$erasers['checkout-firewall'] = array(
			'eraser_friendly_name' => __( 'Checkout Firewall', 'checkout-firewall' ),
			'callback'             => array( $this, 'erase' ),
		);
		return $erasers;
	}

	/**
	 * Erase one bounded page of direct email matches.
	 *
	 * @return array{items_removed:bool,items_retained:bool,messages:list<string>,done:bool}
	 */
	public function erase( string $email_address, int $page = 1 ): array {
		$email = strtolower( trim( sanitize_email( $email_address ) ) );
		if ( $page < 1 || '' === $email || strlen( $email ) > 254 || ! is_email( $email ) ) {
			return $this->result( false, false, array(), true );
		}
		try {
			if ( ! $this->keys->is_healthy() || ! $this->keys->validate_references() ) {
				return $this->result( false, true, array( __( 'Checkout Firewall could not verify retained key material, so matching data was not erased. Use the documented full plugin purge if appropriate.', 'checkout-firewall' ) ), true );
			}
			$variants  = $this->keys->hash_identifier_versions( IdentifierType::EMAIL, $email );
			$remaining = self::LIMIT;
			$removed   = 0;
			foreach ( array( 'events', 'counters', 'blocks' ) as $logical ) {
				if ( $remaining < 1 ) {
					break;
				}
				$ids       = $this->matching_ids( $this->tables->get( $logical ), $variants, $remaining, 'counters' !== $logical );
				$removed  += $this->delete_ids( $this->tables->get( $logical ), $ids );
				$remaining = self::LIMIT - $removed;
			}
			$order_result = $this->payment_attempts->erase_email( $variants, $remaining );
			$removed     += $order_result['removed'];
			if ( 1 === $page && function_exists( 'get_user_by' ) ) {
				$user = get_user_by( 'email', $email );
				if ( false !== $user && ( new TrustedExemptionStore() )->remove_user( $user->ID ) ) {
					++$removed;
				}
			}
			$more = $this->has_match( $variants ) || $order_result['more'];
			return $this->result(
				$removed > 0,
				false,
				array( __( 'An email address alone cannot attribute IP, session, or combined IP-and-email aggregates; those records remain subject to configured retention or full plugin purge.', 'checkout-firewall' ) ),
				! $more
			);
		} catch ( \Throwable $exception ) {
			return $this->result( false, true, array( __( 'Checkout Firewall could not complete this erasure page safely.', 'checkout-firewall' ) ), true );
		}
	}

	/**
	 * Find one bounded list of directly attributable row IDs.
	 *
	 * @param list<array{key_version:int,key_fingerprint:string,identifier_hash:string}> $variants Retained-key hashes.
	 * @return list<int>
	 * @throws \RuntimeException When the bounded selection fails.
	 */
	private function matching_ids( string $table, array $variants, int $limit, bool $has_identifier_type ): array {
		global $wpdb;
		$pairs = array();
		$args  = $has_identifier_type ? array( IdentifierType::EMAIL ) : array();
		foreach ( array_slice( $variants, 0, 32 ) as $variant ) {
			$pairs[] = '(key_version=%d AND identifier_hash=%s)';
			array_push( $args, $variant['key_version'], $variant['identifier_hash'] );
		}
		$args[] = max( 1, min( self::LIMIT, $limit ) );
		$type   = $has_identifier_type ? 'identifier_type=%d AND ' : '';
		$sql    = "SELECT id FROM `{$table}` WHERE {$type}(" . implode( ' OR ', $pairs ) . ') ORDER BY id LIMIT %d';
		$ids    = $wpdb->get_col( $wpdb->prepare( $sql, ...$args ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Closed table and bounded key list.
		if ( ! is_array( $ids ) || '' !== $wpdb->last_error ) {
			throw new \RuntimeException( 'Checkout Firewall erasure selection failed.' );
		}
		return array_map( 'intval', $ids );
	}

	/**
	 * Delete one bounded list of selected IDs.
	 *
	 * @param list<int> $ids Row IDs.
	 * @throws \RuntimeException When deletion fails.
	 */
	private function delete_ids( string $table, array $ids ): int {
		global $wpdb;
		if ( array() === $ids ) {
			return 0;
		}
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$sql          = $wpdb->prepare( "DELETE FROM `{$table}` WHERE id IN ({$placeholders})", ...$ids ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Closed table and numeric IDs.
		$result       = $wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( false === $result ) {
			throw new \RuntimeException( 'Checkout Firewall erasure deletion failed.' );
		}
		return (int) $result;
	}

	/**
	 * Check whether another direct match remains.
	 *
	 * @param list<array{key_version:int,key_fingerprint:string,identifier_hash:string}> $variants Retained-key hashes.
	 */
	private function has_match( array $variants ): bool {
		foreach ( array( 'events', 'counters', 'blocks' ) as $logical ) {
			if ( array() !== $this->matching_ids( $this->tables->get( $logical ), $variants, 1, 'counters' !== $logical ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Build the native WordPress eraser response.
	 *
	 * @param list<string> $messages Response messages.
	 * @return array{items_removed:bool,items_retained:bool,messages:list<string>,done:bool}
	 */
	private function result( bool $removed, bool $retained, array $messages, bool $done ): array {
		return array(
			'items_removed'  => $removed,
			'items_retained' => $retained,
			'messages'       => $messages,
			'done'           => $done,
		);
	}
}
