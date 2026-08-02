<?php
/**
 * Expected invalid checkout-flow proof marker.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\FlowProof;

final class InvalidProofException extends \RuntimeException {
	public function __construct() {
		parent::__construct( 'Invalid checkout-flow proof.' );
	}
}
