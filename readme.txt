=== Checkout Firewall for WooCommerce ===
Contributors: codeprint
Tags: woocommerce, checkout security, card testing, bot protection, recaptcha
Requires at least: 6.8
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 1.0.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Checkout Firewall provides local, explainable checkout-abuse protection before payment processing.

== Description ==

Checkout Firewall protects Classic, Blocks, and supported Store API checkout with signed flow proof, local evidence, velocity controls, recoverable challenges, temporary blocks, and Emergency Mode. WooCommerce is required. New installations begin in Observe Mode; enforcement starts only after an administrator enables Standard Mode.

Free works locally without a Codeprint or Freemius account, and anonymous use creates no licensing traffic. WordPress.org distributes and updates this complete Free plugin. An optional, explicit Freemius connection supports account and purchase surfaces for the separately distributed Premium replacement plugin. Checkout security, shopper, order, gateway, and payment data is not sent to Codeprint or Freemius.

Checkout Firewall never reads or stores card data and never automatically disables a payment gateway. It cannot stop all fraud or guarantee against chargebacks.

Cloudflare is optional. Direct and verified Cloudflare traffic is recognized automatically; another reverse proxy requires explicit trusted ranges.

Checkout Firewall is an independent Codeprint product, not endorsed by WooCommerce, Automattic, Cloudflare, Google, or Freemius.

Built by [Codeprint](https://codeprint.io/).

== Installation ==

1. Upload and activate Checkout Firewall.
2. Open WooCommerce → Checkout Firewall.
3. Leave the new installation in Observe Mode while reviewing what Standard Mode would have done. The suggested review date is advisory; enforcement never starts automatically.
4. Add only necessary trusted exemptions, then explicitly turn on Standard Mode when ready.
5. Review the local health status. The private local browser check works immediately; optionally select Cloudflare Turnstile or Google reCAPTCHA.

== Privacy ==

Checkout Firewall processes abuse signals locally using HMAC-derived identifiers and masked hints, not card data, gateway payloads, or request bodies. Activity and terminal blocks are retained for at most seven days; masked block hints for at most 90 days. A temporary keyed order snapshot is removed after a recorded payment outcome and otherwise follows Activity retention. WordPress email erasure removes directly attributable records. Full uninstall deletion requires explicit administrator opt-in.

Observe Mode stores bounded aggregate would-intervene records while allowing checkout. Exact IPs are keyed; authenticated-user exemptions store local user ID; narrow CIDRs remain readable only for range matching.

The randomized honeypot, signed timing evidence, and default account-free browser proof are evaluated locally. They are supporting automation friction, not proof of humanity.

Selected Turnstile or reCAPTCHA loads only when checkout requires verification. With the default Adaptive timing, ordinary low-risk checkout does not contact the selected provider. A merchant may instead enable Always for guest checkout; active Emergency Mode and eligible Premium Attack state can also prepare verification before Place order. Observe Mode never loads or verifies a remote checkout provider. Server verification omits the optional shopper IP and sends no payment details.

Optional Freemius connection may share administrator name/email, site URL, versions, license/installation identifiers, and activation state for account, purchase, Premium licensing, and Premium updates. Site-profile, diagnostic, extension-inventory, and newsletter permissions are disabled; anonymous activation and Skip send nothing. Free updates come from WordPress.org.

The support snapshot is generated locally and is not uploaded. It excludes site/customer identity, orders, gateways, credentials, requests, logs, and raw errors.

== External services ==

These services are conditional; local protection needs no Codeprint account:

**Freemius.** Contacted only after explicit connection, or by the separately installed Premium plugin for connected licensing/update functions; never per checkout. Anonymous activation and Skip send nothing. Free updates come from WordPress.org. [Service](https://freemius.com/), [Terms](https://freemius.com/terms/), [Privacy](https://freemius.com/privacy/).

**Cloudflare Turnstile.** Contacted only when selected/configured and checkout requires verification under the merchant's challenge timing, active Emergency Mode, or eligible Premium Attack state. Browser/network signals, response token, and merchant secret may be processed; optional shopper IP and payment details are not sent by Checkout Firewall. Observe Mode never contacts Turnstile for checkout verification. [Service](https://developers.cloudflare.com/turnstile/), [Terms](https://www.cloudflare.com/website-terms/), [Privacy](https://www.cloudflare.com/turnstile-privacy-policy/).

**Google reCAPTCHA.** Contacted only when selected/configured and checkout requires verification under the merchant's challenge timing, active Emergency Mode, or eligible Premium Attack state. Browser/network signals, response token, and merchant secret may be processed; optional shopper IP and payment details are not sent by Checkout Firewall. Observe Mode never contacts reCAPTCHA for checkout verification. [Service](https://developers.google.com/recaptcha), [API Terms](https://developers.google.com/terms/), [Terms](https://policies.google.com/terms), [Privacy](https://policies.google.com/privacy).

The local challenge, decisions, records, and support snapshot contact no challenge service or Codeprint scoring API. [Source and build instructions](https://github.com/codeprintagency/Checkout-Firewall).

== Frequently Asked Questions ==

= Does Free protection require an account? =

No. Free protection works locally and Free updates come from WordPress.org. Freemius connection is optional.

= Is Premium code included or locked inside Free? =

No. This WordPress.org plugin is complete and contains no Premium implementation or license-gated local feature. Premium is a separately downloaded GPL-compatible replacement plugin available outside WordPress.org.

= Does Checkout Firewall disable payment gateways? =

No. Checkout Firewall does not disable, hide, reorder, or wrap payment gateways.

= Do I need Cloudflare? =

No. Checkout Firewall works without Cloudflare. If the store uses Cloudflare, the plugin detects a verified Cloudflare connection automatically and safely uses its visitor-address header. Cloudflare can add DDoS and bot mitigation at the network edge before requests reach WordPress.

= Does the plugin work with Checkout Blocks and HPOS? =

Yes. Checkout Firewall declares compatibility with WooCommerce Cart and Checkout Blocks and High-Performance Order Storage.

= Which checkout surfaces are protected in version 1.0.2? =

Classic Checkout, Checkout Blocks, and customer Store API checkout routes are protected. Legacy Classic `order-pay` retries retain WooCommerce authorization but do not receive Checkout Firewall proof, velocity, or challenge evaluation in 1.0.2.

= What happens when I uninstall it? =

Data is preserved by default. Full deletion occurs only after a site administrator explicitly opts in before uninstalling. Multisite deletion is not supported.

= Can a legitimate checkout be challenged or blocked? =

Yes. Automated controls can produce false positives. Challenge recovery works out of the box with the private local check and can instead use verified Turnstile or reCAPTCHA. Review Activity and Blocks, release a local block if appropriate, and stop Emergency Mode when the incident ends.

= Can I see what the plugin would do before it affects checkout? =

Yes. A new installation starts in Observe Mode. The same decision engine measures activity and labels would-challenge and would-block results, but checkout continues and no automatic payment-failure block is created. The merchant must explicitly enable Standard Mode.

= Can I exempt a wholesale customer or office network? =

Yes. Add a trusted exemption for a specific authenticated WordPress user, exact IP, or narrow CIDR. Email addresses cannot grant an exemption because a guest can type any billing email. Exemptions never bypass manual blocks or invalid/replayed checkout proof.

= What does Emergency Mode do? =

For a selected, time-limited period it requires a fresh selected-provider challenge for guest checkout. It does not change payment gateways. If challenge recovery becomes unavailable, Emergency Mode ends automatically and Standard Mode remains active.

== Screenshots ==

1. Overview showing Standard or Observe Mode and local system health.
2. Activity showing synthetic masked checkout interventions and explanations.
3. Blocks showing a synthetic masked local block, release action, and trusted exemptions.
4. Settings showing challenge providers, security notifications, retention, and proxy controls with no secret visible.
5. Privacy & help showing data disclosures, uninstall behavior, and the support snapshot action.

== Support ==

Include the plugin version, software-version section, closed health states, and schedule states from the support snapshot. Do not send payment payloads, request bodies, production database exports, raw shopper identifiers, passwords, secret keys, tokens, or license keys.

== Changelog ==

= 1.0.2 =

* Add adaptive challenge timing, earlier card-testing friction, pre-submit recovery, and safer endpoint limits.

= 1.0.1 =

* Fix Turnstile and reCAPTCHA key saving, provider selection, connection-test visibility, and visible setup-error recovery.

= 1.0.0 =

* Initial release with Classic and Blocks checkout protection, non-enforcing Observe Mode for new installations, narrow trusted exemptions, sustained-activity notices, local automation signals and velocity controls, provider-neutral challenge recovery, Emergency Mode, privacy tools, and bounded support diagnostics.
