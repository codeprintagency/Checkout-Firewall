<?php
/**
 * Versioned local HMAC key storage.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Security;

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- Key-reference inspections use only the closed, prefix-validated TableNames registry and contain no request-derived identifiers.

use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Database\TableNames;

// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode,WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Base64 is safe option serialization for random binary key bytes, not code obfuscation.
final class KeyStore {
	public const OPTION               = 'checkout_firewall_hmac_keys';
	public const BLOCK_ANCHOR_CONTEXT = 'checkout-firewall/block-anchor/v1';
	private const FLOW_PROOF_CONTEXTS = array(
		'checkout-firewall/flow-proof/sign/v1',
		'checkout-firewall/flow-proof/session/v1',
		'checkout-firewall/flow-proof/cart/v1',
		'checkout-firewall/flow-proof/token-id/v1',
		'checkout-firewall/flow-proof/context/v1',
	);
	private const TURNSTILE_CONTEXTS  = array(
		'checkout-firewall/turnstile/config/v1',
		'checkout-firewall/turnstile/state/v1',
		'checkout-firewall/turnstile/cdata/v1',
	);
	private const CHALLENGE_CONTEXTS  = array(
		'checkout-firewall/challenge/state/v1',
		'checkout-firewall/challenge/local-signature/v1',
		'checkout-firewall/challenge/local-key-signature/v1',
		'checkout-firewall/challenge/recaptcha-config/v1',
		'checkout-firewall/checkout-evidence/sign/v1',
	);

	/**
	 * Validated request-local key record.
	 *
	 * @var array<string, mixed>|null
	 */
	private ?array $record = null;

	public function initialize(): bool {
		$stored = get_option( self::OPTION, false );
		if ( false !== $stored ) {
			if ( ! is_array( $stored ) || ! $this->validate_record( $stored ) ) {
				return false;
			}

			$this->record = $stored;
			return true;
		}

		if ( $this->tables_have_keyed_rows() ) {
			return false;
		}

		try {
			$material = random_bytes( 32 );
		} catch ( \Throwable $exception ) {
			return false;
		}

		$record = array(
			'format'          => 1,
			'identifier_keys' => array(
				'current_version' => 1,
				'keys'            => array(
					1 => array(
						'material'       => base64_encode( $material ),
						'fingerprint'    => bin2hex( self::fingerprint( $material ) ),
						'created_at_gmt' => gmdate( 'Y-m-d H:i:s' ),
					),
				),
			),
			'block_anchor'    => array(
				'key_version'          => 1,
				'derived_with_context' => self::BLOCK_ANCHOR_CONTEXT,
				'fingerprint'          => bin2hex( self::fingerprint( self::derive_anchor( $material ) ) ),
			),
		);

		if ( ! add_option( self::OPTION, $record, '', false ) ) {
			$winner = get_option( self::OPTION, false );
			if ( ! is_array( $winner ) || ! $this->validate_record( $winner ) ) {
				return false;
			}

			$this->record = $winner;
			return true;
		}

		$this->record = $record;
		return true;
	}

	public function is_healthy(): bool {
		try {
			$this->load();
			return true;
		} catch ( \RuntimeException $exception ) {
			return false;
		}
	}

	public function current_version(): int {
		$record = $this->load();
		return (int) $record['identifier_keys']['current_version'];
	}

	/**
	 * Return retained identifier-key versions in ascending order.
	 *
	 * @return list<int>
	 */
	public function versions(): array {
		$record   = $this->load();
		$versions = array_map( 'intval', array_keys( $record['identifier_keys']['keys'] ) );
		sort( $versions, SORT_NUMERIC );
		return $versions;
	}

	/**
	 * Derive an identifier under every retained key version.
	 *
	 * @return list<array{key_version:int,key_fingerprint:string,identifier_hash:string}>
	 */
	public function hash_identifier_versions( int $identifier_type, string $canonical_identifier ): array {
		$rows = array();
		foreach ( $this->versions() as $version ) {
			$rows[] = $this->hash_identifier( $identifier_type, $canonical_identifier, $version );
		}
		return $rows;
	}

	/**
	 * Append one new identifier-key version without changing the block anchor.
	 *
	 * @throws \RuntimeException When references, randomness, or storage are unsafe.
	 */
	public function rotate_identifier_key(): int {
		if ( ! $this->validate_references() ) {
			throw new \RuntimeException( 'Checkout Firewall key references are unhealthy.' );
		}
		$record = $this->load();
		$keys   = $record['identifier_keys']['keys'];
		if ( count( $keys ) >= 32 ) {
			throw new \RuntimeException( 'Checkout Firewall retains the maximum key versions.' );
		}
		try {
			$material = random_bytes( 32 );
		} catch ( \Throwable $exception ) {
			throw new \RuntimeException( 'Checkout Firewall could not create identifier key material.' );
		}
		$version                                       = max( array_map( 'intval', array_keys( $keys ) ) ) + 1;
		$record['identifier_keys']['keys'][ $version ] = array(
			'material'       => base64_encode( $material ),
			'fingerprint'    => bin2hex( self::fingerprint( $material ) ),
			'created_at_gmt' => gmdate( 'Y-m-d H:i:s' ),
		);
		$record['identifier_keys']['current_version']  = $version;
		if ( ! $this->validate_record( $record ) || ! update_option( self::OPTION, $record, false ) ) {
			$stored = get_option( self::OPTION, false );
			if ( ! is_array( $stored ) || $stored !== $record ) {
				throw new \RuntimeException( 'Checkout Firewall could not persist identifier key rotation.' );
			}
		}
		$this->record = $record;
		return $version;
	}

	/**
	 * Derive narrowly scoped checkout-flow proof key material.
	 *
	 * @return array{key_version:int,key_fingerprint:string,material:string}
	 * @throws \InvalidArgumentException When the domain is not allowlisted.
	 * @throws \OutOfBoundsException When the selected version is unavailable.
	 */
	public function derive_flow_proof_key( string $context, ?int $version = null ): array {
		if ( ! in_array( $context, self::FLOW_PROOF_CONTEXTS, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported checkout-flow proof key context.' );
		}

		$record  = $this->load();
		$version = $version ?? (int) $record['identifier_keys']['current_version'];
		if ( ! isset( $record['identifier_keys']['keys'][ $version ] ) ) {
			throw new \OutOfBoundsException( 'Checkout-flow proof key version is unavailable.' );
		}

		$root = $this->material( $version );
		return array(
			'key_version'     => $version,
			'key_fingerprint' => self::fingerprint( $root ),
			'material'        => hash_hmac( 'sha256', $context, $root, true ),
		);
	}

	/**
	 * Derive one narrowly scoped Turnstile key.
	 *
	 * @return array{key_version:int,key_fingerprint:string,material:string}
	 * @throws \InvalidArgumentException When the domain is not allowlisted.
	 * @throws \OutOfBoundsException When the selected version is unavailable.
	 */
	public function derive_turnstile_key( string $context, ?int $version = null ): array {
		if ( ! in_array( $context, self::TURNSTILE_CONTEXTS, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported Turnstile key context.' );
		}

		$record  = $this->load();
		$version = $version ?? (int) $record['identifier_keys']['current_version'];
		if ( ! isset( $record['identifier_keys']['keys'][ $version ] ) ) {
			throw new \OutOfBoundsException( 'Turnstile key version is unavailable.' );
		}

		$root = $this->material( $version );
		return array(
			'key_version'     => $version,
			'key_fingerprint' => self::fingerprint( $root ),
			'material'        => hash_hmac( 'sha256', $context, $root, true ),
		);
	}

	/**
	 * Derive one narrowly scoped provider-neutral challenge key.
	 *
	 * @return array{key_version:int,key_fingerprint:string,material:string}
	 * @throws \InvalidArgumentException When the domain is not allowlisted.
	 * @throws \OutOfBoundsException When the selected version is unavailable.
	 */
	public function derive_challenge_key( string $context, ?int $version = null ): array {
		if ( ! in_array( $context, self::CHALLENGE_CONTEXTS, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported challenge key context.' );
		}

		$record  = $this->load();
		$version = $version ?? (int) $record['identifier_keys']['current_version'];
		if ( ! isset( $record['identifier_keys']['keys'][ $version ] ) ) {
			throw new \OutOfBoundsException( 'Challenge key version is unavailable.' );
		}

		$root = $this->material( $version );
		return array(
			'key_version'     => $version,
			'key_fingerprint' => self::fingerprint( $root ),
			'material'        => hash_hmac( 'sha256', $context, $root, true ),
		);
	}

	/**
	 * Derive one closed, versioned key for a caller-owned allowlist.
	 *
	 * @param list<string> $allowed_contexts Exact contexts owned by the caller.
	 * @return array{key_version:int,key_fingerprint:string,material:string}
	 * @throws \InvalidArgumentException When the context is not allowlisted.
	 * @throws \OutOfBoundsException When the selected version is unavailable.
	 */
	public function derive_scoped_key( string $context, array $allowed_contexts, ?int $version = null ): array {
		if ( array() === $allowed_contexts || ! in_array( $context, $allowed_contexts, true ) ) {
			throw new \InvalidArgumentException( 'Unsupported scoped key context.' );
		}
		$record  = $this->load();
		$version = $version ?? (int) $record['identifier_keys']['current_version'];
		if ( ! isset( $record['identifier_keys']['keys'][ $version ] ) ) {
			throw new \OutOfBoundsException( 'Extension key version is unavailable.' );
		}
		$root = $this->material( $version );
		return array(
			'key_version'     => $version,
			'key_fingerprint' => self::fingerprint( $root ),
			'material'        => hash_hmac( 'sha256', $context, $root, true ),
		);
	}

	/**
	 * Derive a versioned pseudonymous identifier.
	 *
	 * @return array{key_version:int, key_fingerprint:string, identifier_hash:string}
	 * @throws \InvalidArgumentException When the identifier input is invalid.
	 */
	public function hash_identifier( int $identifier_type, string $canonical_identifier, ?int $version = null ): array {
		if ( ! IdentifierType::is_valid( $identifier_type ) || '' === $canonical_identifier ) {
			throw new \InvalidArgumentException( 'Invalid identifier input.' );
		}

		$version  = $version ?? $this->current_version();
		$material = $this->material( $version );

		return array(
			'key_version'     => $version,
			'key_fingerprint' => self::fingerprint( $material ),
			'identifier_hash' => hash_hmac( 'sha256', pack( 'n', $identifier_type ) . "\0" . $canonical_identifier, $material, true ),
		);
	}

	/**
	 * Derive the rotation-stable active-block key.
	 *
	 * @return array{active_key_version:int, active_key_fingerprint:string, active_key:string}
	 * @throws \InvalidArgumentException When the identifier input is invalid.
	 */
	public function active_key( int $identifier_type, string $canonical_identifier ): array {
		if ( ! IdentifierType::is_valid( $identifier_type ) || '' === $canonical_identifier ) {
			throw new \InvalidArgumentException( 'Invalid identifier input.' );
		}

		$record         = $this->load();
		$anchor_version = (int) $record['block_anchor']['key_version'];
		$anchor         = self::derive_anchor( $this->material( $anchor_version ) );

		return array(
			'active_key_version'     => $anchor_version,
			'active_key_fingerprint' => self::fingerprint( $anchor ),
			'active_key'             => hash_hmac( 'sha256', pack( 'n', $identifier_type ) . "\0" . $canonical_identifier, $anchor, true ),
		);
	}

	public function validate_references(): bool {
		global $wpdb;

		$record = $this->load();
		$tables = TableNames::from_wordpress()->all();

		foreach ( $tables as $table ) {
			$rows = $wpdb->get_results( "SELECT DISTINCT key_version, key_fingerprint FROM `{$table}` LIMIT 101", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			if ( ! is_array( $rows ) || count( $rows ) > 100 ) {
				return false;
			}

			foreach ( $rows as $row ) {
				$version = isset( $row['key_version'] ) ? (int) $row['key_version'] : 0;
				if ( ! $this->fingerprint_matches( $record, $version, $row['key_fingerprint'] ?? null ) ) {
					return false;
				}
			}
		}

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- The table identifier comes from the closed TableNames registry.
		$block_rows = $wpdb->get_results(
			"SELECT DISTINCT active_key_version, active_key_fingerprint FROM `{$tables['blocks']}` WHERE active_key IS NOT NULL LIMIT 101",
			ARRAY_A
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		if ( ! is_array( $block_rows ) || count( $block_rows ) > 100 ) {
			return false;
		}

		$anchor_version     = (int) $record['block_anchor']['key_version'];
		$anchor_fingerprint = strtolower( (string) $record['block_anchor']['fingerprint'] );
		foreach ( $block_rows as $row ) {
			if ( (int) ( $row['active_key_version'] ?? 0 ) !== $anchor_version
				|| ! is_string( $row['active_key_fingerprint'] ?? null )
				|| ! hash_equals( $anchor_fingerprint, bin2hex( $row['active_key_fingerprint'] ) )
			) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Load and validate the request-local key record.
	 *
	 * @return array<string, mixed>
	 * @throws \RuntimeException When key storage is invalid.
	 */
	private function load(): array {
		if ( null !== $this->record ) {
			return $this->record;
		}

		$stored = get_option( self::OPTION, false );
		if ( ! is_array( $stored ) || ! $this->validate_record( $stored ) ) {
			throw new \RuntimeException( 'Checkout Firewall key storage is invalid.' );
		}

		$this->record = $stored;
		return $stored;
	}

	private function material( int $version ): string {
		$record = $this->load();
		$key    = $record['identifier_keys']['keys'][ $version ] ?? null;
		if ( ! is_array( $key ) ) {
			throw new \RuntimeException( 'Checkout Firewall key version is unavailable.' );
		}

		$material = base64_decode( (string) $key['material'], true );
		if ( false === $material || 32 !== strlen( $material ) ) {
			throw new \RuntimeException( 'Checkout Firewall key material is invalid.' );
		}

		return $material;
	}

	/**
	 * Validate a serialized key record.
	 *
	 * @param array<string, mixed> $record Key record.
	 */
	private function validate_record( array $record ): bool {
		if ( 1 !== ( $record['format'] ?? null )
			|| ! is_array( $record['identifier_keys'] ?? null )
			|| ! is_array( $record['block_anchor'] ?? null )
		) {
			return false;
		}

		$current = $record['identifier_keys']['current_version'] ?? null;
		$keys    = $record['identifier_keys']['keys'] ?? null;
		if ( ! is_int( $current ) || $current < 1 || ! is_array( $keys ) || count( $keys ) < 1 || count( $keys ) > 32 ) {
			return false;
		}

		foreach ( $keys as $version => $key ) {
			if ( ! is_int( $version ) || $version < 1 || ! is_array( $key ) ) {
				return false;
			}

			$material = base64_decode( (string) ( $key['material'] ?? '' ), true );
			if ( false === $material || 32 !== strlen( $material ) ) {
				return false;
			}

			$fingerprint = (string) ( $key['fingerprint'] ?? '' );
			if ( 1 !== preg_match( '/^[a-f0-9]{16}$/D', $fingerprint )
				|| ! hash_equals( $fingerprint, bin2hex( self::fingerprint( $material ) ) )
				|| 1 !== preg_match( '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/D', (string) ( $key['created_at_gmt'] ?? '' ) )
			) {
				return false;
			}
		}

		if ( ! isset( $keys[ $current ] ) ) {
			return false;
		}

		$anchor_version = $record['block_anchor']['key_version'] ?? null;
		if ( ! is_int( $anchor_version ) || ! isset( $keys[ $anchor_version ] )
			|| self::BLOCK_ANCHOR_CONTEXT !== ( $record['block_anchor']['derived_with_context'] ?? null )
		) {
			return false;
		}

		$anchor_material    = base64_decode( (string) $keys[ $anchor_version ]['material'], true );
		$anchor_fingerprint = (string) ( $record['block_anchor']['fingerprint'] ?? '' );
		return is_string( $anchor_material )
			&& 1 === preg_match( '/^[a-f0-9]{16}$/D', $anchor_fingerprint )
			&& hash_equals( $anchor_fingerprint, bin2hex( self::fingerprint( self::derive_anchor( $anchor_material ) ) ) );
	}

	/**
	 * Compare a table-row fingerprint with retained material.
	 *
	 * @param array<string, mixed> $record Key record.
	 * @param mixed                $raw_fingerprint Raw row fingerprint.
	 */
	private function fingerprint_matches( array $record, int $version, $raw_fingerprint ): bool {
		$key = $record['identifier_keys']['keys'][ $version ] ?? null;
		return is_array( $key )
			&& is_string( $raw_fingerprint )
			&& hash_equals( strtolower( (string) $key['fingerprint'] ), bin2hex( $raw_fingerprint ) );
	}

	private function tables_have_keyed_rows(): bool {
		global $wpdb;

		try {
			foreach ( TableNames::from_wordpress()->all() as $table ) {
				// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- The table identifier comes from the closed TableNames registry.
				$row_count = $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
				// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				if ( null === $row_count || (int) $row_count > 0 ) {
					return true;
				}
			}
		} catch ( \Throwable $exception ) {
			return true;
		}

		return false;
	}

	private static function derive_anchor( string $material ): string {
		return hash_hmac( 'sha256', self::BLOCK_ANCHOR_CONTEXT, $material, true );
	}

	private static function fingerprint( string $material ): string {
		return substr( hash( 'sha256', $material, true ), 0, 8 );
	}
}
// phpcs:enable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode,WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
