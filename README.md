# Checkout Firewall for WooCommerce

[Checkout Firewall](https://checkoutfirewall.com/) is a privacy-conscious WordPress plugin that helps WooCommerce stores reduce card testing and automated checkout abuse before payment processing. This repository is the maintained public source mirror for the Free edition submitted to the WordPress.org Plugin Directory.

The complete development repository and Premium implementation are maintained privately. This public repository contains the readable Free runtime source, bundled third-party source and licenses, and the deterministic packaging tool needed to reproduce the submitted Free ZIP.

> **Release status:** WordPress.org review is in progress. Install the plugin only from the official WordPress.org listing after it becomes available. GitHub source archives are not WordPress installation packages.

## What the Free edition does

Checkout Firewall evaluates normal WooCommerce Classic Checkout, Checkout Blocks, and supported Store API checkout routes before a payment attempt reaches the gateway. It combines:

- Observe Mode for seeing what the configured policy would have done before enforcing it;
- signed, short-lived checkout-flow proof;
- randomized honeypot and signed timing evidence;
- keyed IP, billing-email, session, and combined-identity velocity limits;
- local payment-success and payment-failure feedback without inspecting payment data;
- recoverable browser challenges;
- trusted IP, narrow-CIDR, and authenticated-user exemptions;
- temporary blocks, block release, Activity history, Protection Health, and notifications;
- Standard Mode and a manual, time-limited Emergency Mode.

The decision engine can allow, request a challenge, temporarily throttle, or temporarily block a checkout with a stable reason code. Internal exceptions at the checkout boundary fail open. Checkout Firewall never disables, hides, reorders, or wraps payment gateways.

## Challenge providers

Ordinary low-risk checkout does not load a challenge. When local signals require an additional check, a merchant can choose:

- **Local check:** the default, account-free ALTCHA-compatible proof-of-work check, solved in the shopper's browser and verified by the store;
- **Cloudflare Turnstile:** an optional managed provider configured with merchant-owned keys;
- **Google reCAPTCHA v2:** an optional managed alternative configured with merchant-owned keys;
- **No provider:** throttle-only recovery without pretending a challenge was completed.

The local provider makes no remote challenge request. Turnstile or reCAPTCHA loads only after the merchant selects and configures it and a checkout actually requires a challenge.

## Privacy and safety boundaries

- No card number, CVC, payment-gateway payload, or request body is read, stored, logged, hashed, or transmitted.
- Protection decisions run on the merchant's WordPress site; there is no per-order Codeprint scoring API.
- Long-lived identifiers are keyed hashes and administrator-visible hints are masked.
- Activity and terminal-block history is retained for 1, 3, or 7 days; masked block hints for 7, 30, or 90 days.
- Temporary payment-feedback metadata is deleted after a recorded result and otherwise bounded by Activity retention.
- WordPress personal-data erasure removes directly email-attributable records.
- Uninstall preserves data by default; administrators can explicitly authorize a full purge.
- The local support snapshot excludes store/customer identity, orders, gateways, credentials, tokens, requests, logs, and raw errors.

Freemius is contacted only after administrator consent or for connected licensing/update operations. Optional managed challenge providers are contacted only for challenged checkout after merchant configuration. See `readme.txt` for the exact external-service disclosures.

## Free and Premium

Free is a complete local protection product, not a timed trial. Premium is distributed separately and adds automatic Normal, Elevated, Attack, and Recovery states, adaptive thresholds, distributed identity-rotation detection, 90-day analytics, CSV export, webhook alerts, policy transfer, and expanded diagnostics.

All paid plans have the same Premium features and differ only by production activation count. Free protection remains active if a Premium license becomes inactive.

## Requirements and qualified compatibility

- WordPress 6.8 or newer; qualified through WordPress 7.0
- PHP 8.0 or newer
- WooCommerce 10.7 or newer; qualified through WooCommerce 10.9
- WooCommerce Checkout Blocks and High-Performance Order Storage declared compatible

Version 1.0.0 does not evaluate WooCommerce's legacy Classic `order-pay` retry endpoint. Normal Classic Checkout, Checkout Blocks, and supported Store API checkout routes are covered.

## Repository layout

- `checkout-firewall.php` — plugin bootstrap and WordPress metadata
- `src/` — readable Free PHP source
- `assets/` — readable plugin CSS/JavaScript, fonts, and the licensed local challenge runtime
- `vendor/` — the packaged Freemius SDK and its license
- `config/checkout-firewall-build.php` — public, non-secret Free build configuration
- `languages/` — translation template
- `scripts/build-release.php` — deterministic Free ZIP packager
- `readme.txt` — submitted WordPress.org listing and external-service disclosures

The Freemius product ID and public key in the generated configuration are public identifiers, not credentials. Secret keys, customer licenses, dashboard credentials, payment data, and Premium source are not stored here.

## Reproduce the corrected Free review candidate

Requirements are PHP 8.0+ with the Zip extension. From the repository root:

```bash
php scripts/build-release.php
shasum -a 256 dist/checkout-firewall-1.0.0.zip
```

The expected SHA-256 for the exact corrected Free 1.0.0 candidate prepared for the current WordPress.org review is:

```text
d69ae09df89930a6775b98454438fbc022719733959880becbcf8779df12abd1
```

The packager includes only the runtime paths listed in the script, sorts every archive path, fixes timestamps to the ZIP epoch, and fixes Unix file attributes. Repository documentation and tooling are not placed inside the distributable plugin directory.

## Security and support

Do not publish vulnerability details in a GitHub issue. Use GitHub's private vulnerability-reporting workflow or email [jacob@codeprint.io](mailto:jacob@codeprint.io). The same address handles privacy, licensing, refund, and private support questions.

For ordinary reproducible bugs, open a GitHub issue with synthetic reproduction steps and the relevant WordPress, WooCommerce, PHP, plugin, and checkout-surface versions. Never include card data, payment payloads, customer exports, cookies, passwords, keys, tokens, or license credentials.

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License and trademarks

Checkout Firewall is licensed under GPL-2.0-or-later. Bundled third-party notices and licenses are included alongside their source and in `THIRD-PARTY-NOTICES.txt`.

Checkout Firewall is independently published under the Codeprint name. It is not affiliated with or endorsed by Automattic, WooCommerce, WordPress, Cloudflare, Google, Freemius, or any payment processor. WooCommerce and WordPress trademarks belong to their respective owners.
