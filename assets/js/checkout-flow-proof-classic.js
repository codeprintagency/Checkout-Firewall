( function ( window, document, $ ) {
	'use strict';

	const config = window.checkoutFirewallFlowProof;
	const core = window.CheckoutFirewallFlowProofCore;
	if ( ! config || ! core || typeof window.fetch !== 'function' ) {
		return;
	}

	const field = function () { return document.getElementById( config.field ); };
	const client = core.createClient( {
		endpoint: config.endpoint,
		action: config.action,
		refreshLeadMs: config.refreshLeadMs,
		fetch: window.fetch.bind( window ),
		now: Date.now,
		monotonicNow: window.performance && typeof window.performance.now === 'function' ? window.performance.now.bind( window.performance ) : Date.now,
		setTimeout: window.setTimeout.bind( window ),
		clearTimeout: window.clearTimeout.bind( window ),
		isVisible: function () { return document.visibilityState !== 'hidden'; },
		onProof: function ( proof, expiresAt, evidenceToken, honeypotField ) {
			const input = field();
			if ( input ) {
				input.value = proof;
			}
			const evidence = document.getElementById( config.evidenceField );
			const name = document.getElementById( config.honeypotNameField );
			const honeypot = document.getElementById( config.honeypotId );
			if ( evidence ) { evidence.value = evidenceToken; }
			if ( name ) { name.value = honeypotField; }
			if ( honeypot ) {
				honeypot.name = honeypotField;
				honeypot.value = '';
			}
		}
	} );
	let resumeSubmit = false;

	$( function () {
		client.mint();
		$( document.body ).on( 'updated_checkout.checkoutFirewall checkout_error.checkoutFirewall', function () {
			client.invalidateAndMint();
		} );
		window.checkoutFirewallWaitForEvidence = function () { return client.waitUntilEvidenceReady(); };
		$( 'form.checkout' ).on( 'checkout_place_order.checkoutFirewall', function () {
			if ( resumeSubmit ) {
				resumeSubmit = false;
				return true;
			}
			if ( client.isReady() ) {
				return true;
			}
			client.mint().then( function () { return client.waitUntilEvidenceReady(); } ).then( function () {
				resumeSubmit = true;
				$( 'form.checkout' ).trigger( 'submit' );
			} );
			return false;
		} );
	} );

	document.addEventListener( 'visibilitychange', function () {
		if ( document.visibilityState === 'visible' && ! client.isReady() ) {
			client.invalidateAndMint();
		}
	} );
}( window, document, window.jQuery ) );
