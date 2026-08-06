<?php
/**
 * Bounded identity-free Free incident state.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Operations;

final class FreeIncidentState {
	public const OPTION         = 'checkout_firewall_free_incident_state';
	public const QUIET_SECONDS  = 3600;
	public const NOTICE_SECONDS = 604800;

	/**
	 * Read validated incident state.
	 *
	 * @return array<string,mixed>|null
	 */
	public function read(): ?array {
		return $this->normalize( get_option( self::OPTION, false ), time() );
	}

	/**
	 * Open or update an incident from bounded aggregate counts.
	 *
	 * @param array{enforced_challenge:int,enforced_block:int,observed_challenge:int,observed_block:int} $counts Aggregate counts.
	 * @param int|null                                                                                  $now    Current epoch.
	 * @return array<string,mixed>
	 * @throws \RuntimeException When a secure incident identifier cannot be created.
	 */
	public function open( array $counts, ?int $now = null ): array {
		$now = $now ?? time();
		for ( $attempt = 0; $attempt < 3; ++$attempt ) {
			$raw     = get_option( self::OPTION, false );
			$current = $this->normalize( $raw, $now );
			$last    = null !== $current ? strtotime( (string) $current['last_signal_at_gmt'] . ' UTC' ) : false;
			$is_new  = null === $current || false === $last || $last <= $now - self::QUIET_SECONDS;
			$random  = $is_new ? random_bytes( 16 ) : hex2bin( (string) $current['incident_id'] );
			if ( false === $random || 16 !== strlen( $random ) ) {
				throw new \RuntimeException( 'Free incident identifier failed.' );
			}
			$state = array(
				'format'              => 1,
				'revision'            => null === $current ? 0 : (int) $current['revision'],
				'incident_id'         => bin2hex( $random ),
				'status'              => 'open',
				'first_signal_at_gmt' => $is_new ? gmdate( 'Y-m-d H:i:s', $now ) : (string) $current['first_signal_at_gmt'],
				'last_signal_at_gmt'  => gmdate( 'Y-m-d H:i:s', $now ),
				'counts'              => $counts,
				'dismissed_at_gmt'    => $is_new ? '' : (string) $current['dismissed_at_gmt'],
				'email_status'        => $is_new ? 'pending' : (string) $current['email_status'],
				'email_attempts'      => $is_new ? 0 : (int) $current['email_attempts'],
				'last_email_at_gmt'   => null === $current ? '' : (string) $current['last_email_at_gmt'],
			);
			if ( $this->store( $raw, $state ) ) {
				++$state['revision'];
				return $state;
			}
		}
		throw new \RuntimeException( 'Free incident state could not be saved.' );
	}

	public function dismiss( string $incident_id ): bool {
		$state = $this->read();
		if ( null === $state || ! hash_equals( $state['incident_id'], $incident_id ) ) {
			return false;
		}
		$state['dismissed_at_gmt'] = gmdate( 'Y-m-d H:i:s' );
		$this->write( $state );
		return true;
	}

	/**
	 * Persist bounded incident state.
	 *
	 * @param array<string,mixed> $state Incident state.
	 * @throws \RuntimeException When state exceeds the bound or cannot be created.
	 */
	public function write( array $state ): void {
		if ( ! isset( $state['revision'], $state['incident_id'] ) || ! is_int( $state['revision'] ) || 1 > $state['revision'] || ! is_string( $state['incident_id'] ) || strlen( maybe_serialize( $state ) ) > 16384 ) {
			throw new \RuntimeException( 'Free incident state exceeds its bound.' );
		}
		for ( $attempt = 0; $attempt < 3; ++$attempt ) {
			$raw     = get_option( self::OPTION, false );
			$current = $this->normalize( $raw, time() );
			if ( null !== $current ) {
				if ( ! isset( $state['incident_id'] ) || ! is_string( $state['incident_id'] ) || ! hash_equals( $current['incident_id'], $state['incident_id'] ) ) {
					throw new \RuntimeException( 'Free incident state is stale.' );
				}
				if ( $state['revision'] !== $current['revision'] ) {
					$current['dismissed_at_gmt']  = '' !== (string) ( $state['dismissed_at_gmt'] ?? '' ) ? (string) $state['dismissed_at_gmt'] : $current['dismissed_at_gmt'];
					$current['email_status']      = self::later_email_status( (string) $current['email_status'], (string) ( $state['email_status'] ?? 'pending' ) );
					$current['email_attempts']    = max( (int) $current['email_attempts'], (int) ( $state['email_attempts'] ?? 0 ) );
					$current['last_email_at_gmt'] = self::later_date( (string) $current['last_email_at_gmt'], (string) ( $state['last_email_at_gmt'] ?? '' ) );
					$state                        = $current;
				}
			}
			if ( $this->store( $raw, $state ) ) {
				return;
			}
		}
		throw new \RuntimeException( 'Free incident state could not be saved.' );
	}

	/**
	 * Validate persisted state and derive authoritative quiet-period status.
	 *
	 * @return array<string,mixed>|null
	 */
	private function normalize( mixed $value, int $now ): ?array {
		$keys = array( 'format', 'revision', 'incident_id', 'status', 'first_signal_at_gmt', 'last_signal_at_gmt', 'counts', 'dismissed_at_gmt', 'email_status', 'email_attempts', 'last_email_at_gmt' );
		if ( ! is_array( $value ) || array_keys( $value ) !== $keys || 1 !== $value['format'] || ! is_int( $value['revision'] ) || 1 > $value['revision'] || 1 !== preg_match( '/^[a-f0-9]{32}$/D', (string) $value['incident_id'] ) || ! in_array( $value['status'], array( 'open', 'closed' ), true ) || ! self::valid_date( $value['first_signal_at_gmt'] ) || ! self::valid_date( $value['last_signal_at_gmt'] ) || ! is_array( $value['counts'] ) || array( 'enforced_challenge', 'enforced_block', 'observed_challenge', 'observed_block' ) !== array_keys( $value['counts'] ) || ! in_array( $value['email_status'], array( 'pending', 'sending', 'accepted', 'failed' ), true ) || ! is_int( $value['email_attempts'] ) || 0 > $value['email_attempts'] || 2 < $value['email_attempts'] || 16384 < strlen( maybe_serialize( $value ) ) ) {
			return null;
		}
		foreach ( $value['counts'] as $count ) {
			if ( ! is_int( $count ) || 0 > $count ) {
				return null;
			}
		}
		if ( ( '' !== $value['dismissed_at_gmt'] && ! self::valid_date( $value['dismissed_at_gmt'] ) ) || ( '' !== $value['last_email_at_gmt'] && ! self::valid_date( $value['last_email_at_gmt'] ) ) ) {
			return null;
		}
		$last = strtotime( $value['last_signal_at_gmt'] . ' UTC' );
		if ( false !== $last && $last <= $now - self::QUIET_SECONDS ) {
			$value['status'] = 'closed';
		}
		return $value;
	}

	/**
	 * Atomically persist an exact previous incident revision.
	 *
	 * @param array<string,mixed> $next Next incident state.
	 */
	private function store( mixed $raw, array $next ): bool {
		++$next['revision'];
		if ( false === $raw ) {
			return add_option( self::OPTION, $next, '', false );
		}
		global $wpdb;
		if ( is_object( $wpdb ) && method_exists( $wpdb, 'query' ) && method_exists( $wpdb, 'prepare' ) ) {
			$result = $wpdb->query( $wpdb->prepare( "UPDATE `{$wpdb->options}` SET option_value=%s WHERE option_name=%s AND option_value=%s", maybe_serialize( $next ), self::OPTION, maybe_serialize( $raw ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			wp_cache_delete( self::OPTION, 'options' );
			return 1 === $result;
		}
		return update_option( self::OPTION, $next, false );
	}

	private static function valid_date( mixed $value ): bool {
		return is_string( $value ) && 1 === preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', $value ) && false !== strtotime( $value . ' UTC' );
	}

	private static function later_email_status( string $current, string $proposed ): string {
		$rank = array(
			'pending'  => 0,
			'sending'  => 1,
			'failed'   => 2,
			'accepted' => 3,
		);
		return ( $rank[ $proposed ] ?? 0 ) > ( $rank[ $current ] ?? 0 ) ? $proposed : $current;
	}

	private static function later_date( string $current, string $proposed ): string {
		if ( '' === $proposed ) {
			return $current;
		}
		return '' === $current || strcmp( $proposed, $current ) > 0 ? $proposed : $current;
	}
}
