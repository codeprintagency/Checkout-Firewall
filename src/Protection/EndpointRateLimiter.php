<?php
/**
 * Local rate limiter for public checkout-support endpoints.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Protection;

use Codeprint\CheckoutFirewall\Checkout\CheckoutContext;
use Codeprint\CheckoutFirewall\Checkout\CheckoutSurface;
use Codeprint\CheckoutFirewall\Data\IdentifierType;
use Codeprint\CheckoutFirewall\Support\SafeLogger;

final class EndpointRateLimiter {
	public function __construct(
		private IdentityRegistry $identities,
		private CounterRepository $counters
	) {}

	/**
	 * Claim one endpoint request and return its local limit result.
	 *
	 * @return array{allowed:bool,retry_after:int}
	 */
	public function allow( int $counter_type, int $session_limit, int $ip_limit ): array {
		try {
			$context = new CheckoutContext( CheckoutSurface::CLASSIC, is_user_logged_in(), 0, false, 0 );
			$this->identities->record( $context, null );
			$all = $this->identities->read( $context );
			$ids = array_intersect_key( $all, array_flip( array( IdentifierType::SESSION, IdentifierType::IP ) ) );
			$this->counters->increment( $ids, $counter_type );
			foreach ( array(
				IdentifierType::SESSION => $session_limit,
				IdentifierType::IP      => $ip_limit,
			) as $type => $limit ) {
				if ( ! isset( $ids[ $type ] ) ) {
					continue;
				}
				$total = $this->counters->totals( array( $type => $ids[ $type ] ), $counter_type, 60 );
				if ( (int) ( $total[ $type ] ?? 0 ) > $limit ) {
					return array(
						'allowed'     => false,
						'retry_after' => 60,
					);
				}
			}
		} catch ( \Throwable $exception ) {
			// Availability boundary: a limiter fault must not break checkout support.
			SafeLogger::exception( 'endpoint_rate_limiter_failed', $exception );
		}
		return array(
			'allowed'     => true,
			'retry_after' => 0,
		);
	}
}
