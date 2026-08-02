( function ( window, document, $ ) {
	'use strict';
	const config = window.checkoutFirewallTurnstile;
	const core = window.CheckoutFirewallTurnstileCore;
	if ( ! config || ! core || ! $ || typeof window.fetch !== 'function' ) { return; }
	const field = function ( id ) { return document.getElementById( id ); };
	const client = core.createClient( {
		endpoint: config.endpoint, fetch: window.fetch.bind( window ), document: document,
		strings: config.strings,
		turnstile: function () { return window.turnstile || null; },
		mount: function () {
			let node = field( config.mount );
			if ( ! node ) { node = document.createElement( 'div' ); node.id = config.mount; node.className = 'cf-turnstile-panel'; node.hidden = true; const form = document.querySelector( 'form.checkout' ); if ( form ) { form.prepend( node ); } }
			return node;
		},
		isExpress: function () { return !! document.querySelector( '.wc-stripe-express-checkout-element iframe, .wc-block-components-express-payment, .ppc-button-wrapper iframe' ); },
		onSolved: function ( token, state ) {
			const tokenField = field( config.tokenField ); const stateField = field( config.stateField );
			if ( tokenField && stateField ) { tokenField.value = token; stateField.value = state; $( 'form.checkout' ).trigger( 'submit' ); }
		},
		onReset: function () { const token = field( config.tokenField ); const state = field( config.stateField ); if ( token ) { token.value = ''; } if ( state ) { state.value = ''; } }
	} );
	$( document.body ).on( 'checkout_error.checkoutFirewallTurnstile', function () { client.reset(); client.begin(); } );
	$( document.body ).on( 'updated_checkout.checkoutFirewallTurnstile', function () { if ( client.getState() === 'submitting' ) { client.reset(); } } );
}( window, document, window.jQuery ) );
