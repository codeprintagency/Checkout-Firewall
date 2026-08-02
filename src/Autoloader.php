<?php
/**
 * Minimal production autoloader.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall;

final class Autoloader {
	private const PREFIX = 'Codeprint\\CheckoutFirewall\\';

	private string $source_directory;

	private function __construct( string $project_directory ) {
		$source = realpath( $project_directory . '/src' );

		if ( false === $source || ! is_dir( $source ) ) {
			throw new \RuntimeException( 'Checkout Firewall source directory is unavailable.' );
		}

		$this->source_directory = rtrim( $source, DIRECTORY_SEPARATOR );
	}

	public static function register( string $project_directory ): self {
		$loader = new self( $project_directory );

		if ( ! spl_autoload_register( array( $loader, 'load' ), true, false ) ) {
			throw new \RuntimeException( 'Checkout Firewall autoloader registration failed.' );
		}

		return $loader;
	}

	public function load( string $class_name ): void {
		if ( 0 !== strncmp( $class_name, self::PREFIX, strlen( self::PREFIX ) ) ) {
			return;
		}

		$relative_class = substr( $class_name, strlen( self::PREFIX ) );

		if ( '' === $relative_class
			|| ! preg_match( '/^[A-Za-z_][A-Za-z0-9_]*(?:\\\\[A-Za-z_][A-Za-z0-9_]*)*$/D', $relative_class )
		) {
			return;
		}

		$candidate = $this->source_directory . DIRECTORY_SEPARATOR
			. str_replace( '\\', DIRECTORY_SEPARATOR, $relative_class ) . '.php';
		$file      = realpath( $candidate );

		if ( false === $file || ! is_readable( $file ) ) {
			return;
		}

		$allowed_prefix = $this->source_directory . DIRECTORY_SEPARATOR;
		if ( 0 !== strncmp( $file, $allowed_prefix, strlen( $allowed_prefix ) ) ) {
			return;
		}

		require_once $file;
	}
}
