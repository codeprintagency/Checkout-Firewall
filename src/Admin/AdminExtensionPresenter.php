<?php
/**
 * Narrow presentation contract for separately packaged extensions.
 *
 * @package Codeprint\CheckoutFirewall
 */

declare(strict_types=1);

namespace Codeprint\CheckoutFirewall\Admin;

interface AdminExtensionPresenter {
	public function render( string $view ): void;

	public function status_copy( string $status ): ?string;

	public function license_label(): string;

	public function privacy_policy_paragraph(): string;
}
