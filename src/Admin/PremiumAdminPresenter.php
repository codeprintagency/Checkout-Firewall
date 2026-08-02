<?php
/**
 * Narrow shared-core presentation contract implemented only by Premium code.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

interface PremiumAdminPresenter {
	public function render( string $view ): void;

	public function status_copy( string $status ): ?string;

	public function license_label(): string;

	public function privacy_policy_paragraph(): string;
}
