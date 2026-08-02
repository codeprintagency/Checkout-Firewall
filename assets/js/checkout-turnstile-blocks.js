( function ( window, document ) {
	'use strict';
	const core = window.CheckoutFirewallTurnstileCore;
	const data = window.wc && window.wc.wcSettings ? window.wc.wcSettings.getSetting( 'checkout-firewall-flow-proof_data', {} ) : {};
	if ( ! core || ! data.turnstileEnabled || ! window.wp || ! window.wp.data ) { return; }
	const store = 'wc/store/checkout';
	const paymentStore = 'wc/store/payment';
	const extensionData = window.checkoutFirewallExtensionData || {
		flow_proof: '',
		turnstile_token: '',
		turnstile_state: ''
	};
	window.checkoutFirewallExtensionData = extensionData;
	const setData = function ( token, state ) {
		extensionData.turnstile_token = token;
		extensionData.turnstile_state = state;
		const dispatch = window.wp.data.dispatch( store );
		if ( dispatch && typeof dispatch.setExtensionData === 'function' ) { dispatch.setExtensionData( data.namespace, Object.assign( {}, extensionData ) ); }
	};
	setData( '', '' );
	const client = core.createClient( {
		endpoint: data.turnstileEndpoint, fetch: window.fetch.bind( window ), document: document,
		strings: data.turnstileStrings,
		turnstile: function () { return window.turnstile || null; },
		mount: function () { let node = document.getElementById( 'cf-turnstile-blocks' ); if ( ! node ) { node = document.createElement( 'div' ); node.id = 'cf-turnstile-blocks'; node.className = 'cf-turnstile-panel'; node.hidden = true; const button = document.querySelector( '.wc-block-components-checkout-place-order-button' ); if ( button && button.parentNode ) { button.parentNode.insertBefore( node, button ); } } return node; },
		isExpress: function () { const selector = window.wp.data.select( paymentStore ); return !! ( selector && typeof selector.isExpressPaymentStarted === 'function' && selector.isExpressPaymentStarted() ); },
		onSolved: function ( token, state ) {
			setData( token, state );
			const retry = function () { const button = document.querySelector( '.wc-block-components-checkout-place-order-button' ); if ( button ) { button.click(); } };
			const refresh = window.checkoutFirewallRefreshFlowProof;
			if ( typeof refresh === 'function' ) {
				Promise.resolve( refresh() ).then( retry, retry );
			} else {
				retry();
			}
		},
		onReset: function () { setData( '', '' ); }
	} );
	const checkoutEvents = window.wc && window.wc.blocksCheckoutEvents && window.wc.blocksCheckoutEvents.checkoutEvents;
	if ( checkoutEvents && typeof checkoutEvents.onCheckoutFail === 'function' ) {
		checkoutEvents.onCheckoutFail( function () {
			if ( client.getState() === 'submitting' ) { client.reset(); }
			return { type: 'success' };
		} );
	}
	if ( window.wp.apiFetch && typeof window.wp.apiFetch.use === 'function' ) {
		window.wp.apiFetch.use( function ( options, next ) {
			const path = options && typeof options.path === 'string' ? options.path.split( '?' )[ 0 ] : '';
			const checkoutPath = /^\/wc\/store\/v1\/checkout(?:\/\d+)?$/.test( path );
			const inspect = function ( body ) {
				if ( checkoutPath && body && body.code === 'checkout_firewall_challenge_required' ) {
					if ( client.getState() === 'submitting' ) { client.reset(); }
					client.begin();
				}
			};
			return next( options ).then( function ( response ) {
				if ( response && response.ok === false && checkoutPath && typeof response.clone === 'function' ) {
					response.clone().json().then( function ( body ) {
						inspect( body );
					} ).catch( function () {} );
				}
				return response;
			}, function ( error ) {
				inspect( error );
				if ( checkoutPath && error && typeof error.clone === 'function' ) { error.clone().json().then( inspect ).catch( function () {} ); }
				throw error;
			} );
		} );
	}
	let previous = '';
	window.wp.data.subscribe( function () { const selector = window.wp.data.select( store ); if ( ! selector || typeof selector.getCheckoutStatus !== 'function' ) { return; } const status = selector.getCheckoutStatus(); if ( status === 'idle' && previous && previous !== 'idle' && client.getState() === 'submitting' ) { client.reset(); } const payment = window.wp.data.select( paymentStore ); if ( payment && typeof payment.isExpressPaymentStarted === 'function' && payment.isExpressPaymentStarted() ) { client.reset(); } previous = status; } );
}( window, document ) );
