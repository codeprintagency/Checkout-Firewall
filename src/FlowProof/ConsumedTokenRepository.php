<?php
/**
 * Atomic one-time checkout-flow proof consumption.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

use Codeprint\CheckoutFirewall\Database\TableNames;

final class ConsumedTokenRepository {
	/**
	 * Return true for the first consumption and false for replay.
	 *
	 * @param array{status:string,token_hash?:string,context_hash?:string,key_version?:int,key_fingerprint?:string,expires_at?:int} $validation Valid proof row.
	 * @throws \InvalidArgumentException When the validated row is incomplete.
	 * @throws \RuntimeException When the database result cannot be attributed.
	 */
	public function consume( array $validation ): bool {
		global $wpdb;

		if ( 'valid' !== $validation['status'] || ! isset( $validation['token_hash'], $validation['context_hash'], $validation['key_version'], $validation['key_fingerprint'], $validation['expires_at'] )
			|| 32 !== strlen( $validation['token_hash'] ) || 32 !== strlen( $validation['context_hash'] ) || 8 !== strlen( $validation['key_fingerprint'] )
		) {
			throw new \InvalidArgumentException( 'Invalid consumed-token row.' );
		}

		$table  = TableNames::from_wordpress()->get( 'consumed_tokens' );
		$query  = $wpdb->prepare(
			"INSERT IGNORE INTO `{$table}` (token_hash,context_hash,key_version,key_fingerprint,consumed_at_gmt,expires_at_gmt) VALUES (%s,%s,%d,%s,%s,%s)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Closed table registry.
			$validation['token_hash'],
			$validation['context_hash'],
			$validation['key_version'],
			$validation['key_fingerprint'],
			gmdate( 'Y-m-d H:i:s' ),
			gmdate( 'Y-m-d H:i:s', $validation['expires_at'] )
		);
		$result = $wpdb->query( $query ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic security write.
		if ( 1 === $result ) {
			return true;
		}
		if ( false === $result ) {
			throw new \RuntimeException( 'Checkout-flow proof consumption failed.' );
		}

		$exists = $wpdb->get_var(
			$wpdb->prepare( "SELECT id FROM `{$table}` WHERE token_hash = %s LIMIT 1", $validation['token_hash'] ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Closed table registry.
		); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Exact replay diagnosis after ignored insert.
		if ( null !== $exists ) {
			return false;
		}

		throw new \RuntimeException( 'Checkout-flow proof consumption was not attributable.' );
	}
}
