=== Checkout Firewall for WooCommerce ===
Contributors: codeprint
Tags: woocommerce, checkout, security, abuse prevention, turnstile
Requires at least: 6.8
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Checkout Firewall provides local, explainable checkout-abuse protection before payment processing.

== Description ==

Checkout Firewall protects Classic Checkout and WooCommerce Checkout Blocks with local checkout-flow proof, automatic randomized honeypot and timing signals, bounded velocity controls, provider-neutral recoverable challenges, explicit local blocks, and manual time-boxed Emergency Mode. New installations begin in non-enforcing Observe Mode so a merchant can review what Standard Mode would have challenged or stopped before enabling enforcement. Observe Mode never turns itself off.

Free also includes trusted exemptions for an exact IP, a narrow IPv4 or IPv6 network, or an authenticated WordPress user. They apply only to automatic velocity and payment-failure lockouts; manual blocks and invalid or replayed proof remain authoritative. Ten intervention signals in ten minutes create a local incident notice and, when enabled, a rate-limited WordPress email. This is an activity signal, not a fraud determination.

Free protection works locally without a Codeprint or Freemius account, and anonymous use creates no licensing traffic. An administrator can optionally connect licensing and updates after reviewing a Freemius consent screen. Checkout Firewall does not send security events, checkout data, shopper identifiers, orders, gateway data, Turnstile data, or payment data to Codeprint or Freemius.

Checkout Firewall never reads or stores card data and never automatically disables a payment gateway. It cannot stop all fraud or guarantee chargebacks.

Cloudflare is optional. Checkout Firewall automatically recognizes direct traffic and verified Cloudflare connections; custom proxy configuration is needed only for another reverse proxy or CDN. Cloudflare can provide an additional edge layer for DDoS and bot mitigation before requests reach WordPress, while Checkout Firewall remains active without it.

Checkout Firewall is an independent product by Codeprint and is not affiliated with or endorsed by WooCommerce or Automattic. WooCommerce is a trademark of Automattic Inc. Cloudflare and Turnstile are trademarks of Cloudflare, Inc.

== Installation ==

1. Upload and activate Checkout Firewall.
2. Open WooCommerce → Checkout Firewall.
3. Leave the new installation in Observe Mode while reviewing what Standard Mode would have done. The suggested review date is advisory; enforcement never starts automatically.
4. Add only necessary trusted exemptions, then explicitly turn on Standard Mode when ready.
5. Review the local health status. The private local browser check works immediately; optionally select Cloudflare Turnstile or Google reCAPTCHA.

== Privacy ==

Checkout Firewall processes checkout-abuse signals locally. It stores HMAC-derived identifiers and bounded masked hints, not raw card data, gateway payloads, or request bodies. A temporary keyed payment-feedback snapshot may be attached to a pending order. It is deleted after a recorded payment success or failure and otherwise expires within the configured Activity retention period of no more than seven days. Security-event and terminal block history is retained for no more than seven days; masked block hints are retained for no more than 90 days. WordPress email erasure includes directly email-attributable payment-feedback snapshots, and an explicitly authorized full uninstall removes all plugin-owned snapshots.

Observe Mode stores bounded aggregate records of what Standard Mode would have challenged or blocked while allowing checkout to continue. Trusted exact IPs are keyed immediately, authenticated-user exemptions store the local user ID, and a narrow CIDR is stored raw only because network-range matching cannot be one-way. Local incident state stores separate actual/observed counts and no shopper subject.

Checkout pages include a randomized honeypot and signed, short-lived timing evidence. They are evaluated locally only as supporting automation signals. The default private computational check adds modest account-free friction in the shopper browser and is verified by the store without contacting an outside challenge provider. It does not prove a human or replace the stronger optional Turnstile integration against optimized or distributed attackers.

When configured and selected, Cloudflare Turnstile or Google reCAPTCHA loads only after a challenge and may process browser and network information under that provider's terms. Checkout Firewall omits the optional shopper IP from server-side Turnstile verification and sends no payment details to either provider.

Optional Freemius connection may share the administrator name and email, site URL and language, product version and state, WordPress and PHP versions, and installation or license identifiers required for licensing and updates. Checkout Firewall does not request marketing email, diagnostic tracking, installed plugin or theme inventory, or affiliation data.

The support snapshot is generated locally and is not uploaded. It excludes store identity, administrators, customers, shopper identifiers, orders, gateways, keys, tokens, requests, logs, and raw errors.

External service terms: [Cloudflare Privacy Policy](https://www.cloudflare.com/privacypolicy/), [Google Privacy Policy](https://policies.google.com/privacy), and [Freemius Privacy Policy](https://freemius.com/privacy/). Source and reproducible build instructions are maintained in the [Checkout Firewall repository](https://github.com/codeprintagency/Checkout-Firewall).

== Frequently Asked Questions ==

= Does Free protection require an account? =

No. Free protection works locally. Licensing and update connection is optional.

= Does Checkout Firewall disable payment gateways? =

No. Checkout Firewall does not disable, hide, reorder, or wrap payment gateways.

= Do I need Cloudflare? =

No. Checkout Firewall works without Cloudflare. If the store uses Cloudflare, the plugin detects a verified Cloudflare connection automatically and safely uses its visitor-address header. Cloudflare can add DDoS and bot mitigation at the network edge before requests reach WordPress.

= Does the plugin work with Checkout Blocks and HPOS? =

Yes. Checkout Firewall declares compatibility with WooCommerce Cart and Checkout Blocks and High-Performance Order Storage.

= Which checkout surfaces are protected in version 1.0.0? =

Checkout Firewall protects the normal Classic Checkout flow, Checkout Blocks, and the customer Store API checkout routes, including the Store API existing-order route. WooCommerce's legacy Classic `order-pay` payment-retry endpoint is not protected in version 1.0.0. Existing WooCommerce authorization still applies there, but Checkout Firewall does not add its proof, velocity, or challenge decision to that legacy endpoint.

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

= How do I roll back? =

Deactivate Checkout Firewall, verify the checksum of the previously tested package, replace the plugin files, and reactivate it. Version 1.0.0 keeps schema v1 and preserves data by default.

= Where can I get diagnostic information? =

Open WooCommerce → Checkout Firewall → Privacy & help and download the privacy-bounded support snapshot.

== Screenshots ==

1. Overview showing Standard or Observe Mode and local system health.
2. Activity showing synthetic masked checkout interventions and explanations.
3. Blocks showing a synthetic masked local block, release action, and trusted exemptions.
4. Settings showing challenge providers, security notifications, retention, and proxy controls with no secret visible.
5. Privacy & help showing data disclosures, uninstall behavior, and the support snapshot action.

== Support ==

Include the plugin version, software-version section, closed health states, and schedule states from the support snapshot. Do not send payment payloads, request bodies, production database exports, raw shopper identifiers, passwords, secret keys, tokens, or license keys.

= Is card data collected? =

No. Checkout Firewall must never read, store, log, hash, or transmit card data.

== Changelog ==

= 1.0.0 =

* Initial Free release candidate with Classic and Blocks checkout protection, non-enforcing Observe Mode for new installations, narrow trusted exemptions, sustained-activity notices, local automation signals and velocity controls, provider-neutral challenge recovery, Emergency Mode, privacy tools, and bounded support diagnostics.
