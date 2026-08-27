( function ( window, document ) {
	'use strict';
	const core = window.CheckoutFirewallChallengeCore;
	const data = window.wc && window.wc.wcSettings ? window.wc.wcSettings.getSetting( 'checkout-firewall-flow-proof_data', {} ) : {};
	if ( ! core || ! data.challengeEndpoint || ! window.wp || ! window.wp.data ) { return; }
	const store = 'wc/store/checkout'; const paymentStore = 'wc/store/payment';
	const extensionData = window.checkoutFirewallExtensionData || { flow_proof: '', challenge_token: '', challenge_state: '', evidence_token: '', honeypot_field: '', honeypot_value: '' };
	window.checkoutFirewallExtensionData = extensionData;
	const setData = function ( token, state ) { extensionData.challenge_token = token; extensionData.challenge_state = state; const dispatch = window.wp.data.dispatch( store ); if ( dispatch && typeof dispatch.setExtensionData === 'function' ) { dispatch.setExtensionData( data.namespace, Object.assign( {}, extensionData ) ); } };
	setData( '', '' );
	const client = core.createClient( {
		endpoint: data.challengeEndpoint, fetch: window.fetch.bind( window ), document: document, strings: data.challengeStrings,
		preflight: !! data.preflight, surface: data.challengeSurface || 'blocks', autoSubmit: ! data.preflight,
		localScript: data.localScript, localWorker: data.localWorker, localStyle: data.localStyle, language: data.language,
		mount: function () { let node = document.getElementById( 'cf-challenge-blocks' ); if ( ! node ) { node = document.createElement( 'div' ); node.id = 'cf-challenge-blocks'; node.className = 'cf-challenge-panel'; node.hidden = true; const button = document.querySelector( '.wc-block-components-checkout-place-order-button' ); if ( button && button.parentNode ) { button.parentNode.insertBefore( node, button ); } } return node; },
		isExpress: function () { const selector = window.wp.data.select( paymentStore ); return !! ( selector && typeof selector.isExpressPaymentStarted === 'function' && selector.isExpressPaymentStarted() ); },
		onSolved: function ( token, state ) { setData( token, state ); if ( data.preflight ) { return; } const retry = function () { const button = document.querySelector( '.wc-block-components-checkout-place-order-button' ); if ( button ) { button.click(); } }; const wait = function () { const ready = window.checkoutFirewallWaitForEvidence; return typeof ready === 'function' ? ready() : undefined; }; const refresh = window.checkoutFirewallRefreshFlowProof; const prepared = typeof refresh === 'function' ? Promise.resolve( refresh() ) : Promise.resolve(); prepared.then( wait ).then( retry, retry ); },
		onReset: function () { setData( '', '' ); }
	} );
	if ( window.wp.apiFetch && typeof window.wp.apiFetch.use === 'function' ) {
		window.wp.apiFetch.use( function ( options, next ) { const path = options && typeof options.path === 'string' ? options.path.split( '?' )[ 0 ] : ''; const checkoutPath = /^\/wc\/store\/v1\/checkout(?:\/\d+)?$/.test( path ); const inspect = function ( body ) { if ( checkoutPath && body && body.code === 'checkout_firewall_challenge_required' ) { if ( client.getState() === 'submitting' ) { client.reset(); } client.begin(); } }; return next( options ).then( function ( response ) { if ( response && response.ok === false && checkoutPath && typeof response.clone === 'function' ) { response.clone().json().then( inspect ).catch( function () {} ); } return response; }, function ( error ) { inspect( error ); if ( checkoutPath && error && typeof error.clone === 'function' ) { error.clone().json().then( inspect ).catch( function () {} ); } throw error; } ); } );
	}
	let previous = '';
	window.wp.data.subscribe( function () { const selector = window.wp.data.select( store ); if ( ! selector || typeof selector.getCheckoutStatus !== 'function' ) { return; } const status = selector.getCheckoutStatus(); if ( status === 'idle' && previous && previous !== 'idle' && client.getState() === 'submitting' ) { client.reset(); } const payment = window.wp.data.select( paymentStore ); if ( payment && typeof payment.isExpressPaymentStarted === 'function' && payment.isExpressPaymentStarted() ) { client.reset(); } previous = status; } );
	if ( data.preflight ) {
		let attempts = 0;
		const start = function () { if ( document.querySelector( '.wc-block-components-checkout-place-order-button' ) || attempts >= 40 ) { client.begin(); return; } ++attempts; window.setTimeout( start, 250 ); };
		start();
	}
}( window, document ) );
