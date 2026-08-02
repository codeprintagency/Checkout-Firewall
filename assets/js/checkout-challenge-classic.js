( function ( window, document, $ ) {
	'use strict';
	const config = window.checkoutFirewallChallenge;
	const core = window.CheckoutFirewallChallengeCore;
	if ( ! config || ! core || ! $ || typeof window.fetch !== 'function' ) { return; }
	const field = function ( id ) { return document.getElementById( id ); };
	let standardCheckoutStarted = false;
	const client = core.createClient( {
		endpoint: config.endpoint, fetch: window.fetch.bind( window ), document: document, strings: config.strings,
		localScript: config.localScript, localWorker: config.localWorker, localStyle: config.localStyle, language: config.language,
		mount: function () { let node = field( config.mount ); if ( ! node ) { node = document.createElement( 'div' ); node.id = config.mount; node.className = 'cf-challenge-panel'; node.hidden = true; const form = document.querySelector( 'form.checkout' ); if ( form ) { form.prepend( node ); } } return node; },
		isExpress: function () { return ! standardCheckoutStarted && !! document.querySelector( '.wc-stripe-express-checkout-element iframe, .wc-block-components-express-payment, .ppc-button-wrapper iframe' ); },
		onSolved: function ( token, state ) { const tokenField = field( config.tokenField ); const stateField = field( config.stateField ); if ( tokenField && stateField ) { tokenField.value = token; stateField.value = state; const retry = function () { $( 'form.checkout' ).trigger( 'submit' ); }; const wait = window.checkoutFirewallWaitForEvidence; if ( typeof wait === 'function' ) { Promise.resolve( wait() ).then( retry, retry ); } else { retry(); } } },
		onReset: function () { const token = field( config.tokenField ); const state = field( config.stateField ); if ( token ) { token.value = ''; } if ( state ) { state.value = ''; } }
	} );
	$( 'form.checkout' ).on( 'checkout_place_order.checkoutFirewallChallenge', function () { standardCheckoutStarted = true; return true; } );
	$( document.body ).on( 'checkout_error.checkoutFirewallChallenge', function () { client.reset(); client.begin(); standardCheckoutStarted = false; } );
	$( document.body ).on( 'updated_checkout.checkoutFirewallChallenge', function () { if ( client.getState() === 'submitting' ) { client.reset(); } } );
}( window, document, window.jQuery ) );
