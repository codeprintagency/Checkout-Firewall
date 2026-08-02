( function ( window, document ) {
	'use strict';

	const core = window.CheckoutFirewallFlowProofCore;
	const data = window.wc && window.wc.wcSettings && typeof window.wc.wcSettings.getSetting === 'function'
		? window.wc.wcSettings.getSetting( 'checkout-firewall-flow-proof_data', {} )
		: {};
	if ( ! core || ! data.endpoint || ! window.wp || ! window.wp.data || typeof window.fetch !== 'function' ) {
		return;
	}

	const checkoutStore = 'wc/store/checkout';
	const cartStore = 'wc/store/cart';
	const extensionData = window.checkoutFirewallExtensionData || {
		flow_proof: '',
		turnstile_token: '',
		turnstile_state: '',
		challenge_token: '',
		challenge_state: '',
		evidence_token: '',
		honeypot_field: '',
		honeypot_value: ''
	};
	window.checkoutFirewallExtensionData = extensionData;
	const dispatchProof = function ( proof, expiresAt, evidenceToken, honeypotField ) {
		extensionData.flow_proof = proof;
		extensionData.evidence_token = evidenceToken;
		extensionData.honeypot_field = honeypotField;
		extensionData.honeypot_value = '';
		const dispatcher = window.wp.data.dispatch( checkoutStore );
		if ( dispatcher && typeof dispatcher.setExtensionData === 'function' ) {
			dispatcher.setExtensionData( data.namespace, Object.assign( {}, extensionData ) );
		}
	};
	const client = core.createClient( {
		endpoint: data.endpoint,
		action: data.action,
		refreshLeadMs: data.refreshLeadMs,
		fetch: window.fetch.bind( window ),
		now: Date.now,
		monotonicNow: window.performance && typeof window.performance.now === 'function' ? window.performance.now.bind( window.performance ) : Date.now,
		setTimeout: window.setTimeout.bind( window ),
		clearTimeout: window.clearTimeout.bind( window ),
		isVisible: function () { return document.visibilityState !== 'hidden'; },
		onProof: dispatchProof
	} );
	window.checkoutFirewallRefreshFlowProof = function () { return client.invalidateAndMint(); };
	window.checkoutFirewallWaitForEvidence = function () { return client.waitUntilEvidenceReady(); };
	let lastCart = '';
	let lastStatus = '';
	let initialized = false;

	window.wp.data.subscribe( function () {
		const cartSelector = window.wp.data.select( cartStore );
		const checkoutSelector = window.wp.data.select( checkoutStore );
		if ( ! cartSelector || ! checkoutSelector || typeof cartSelector.getCartData !== 'function' ) {
			return;
		}
		const cart = cartSelector.getCartData();
		const items = cart && Array.isArray( cart.items ) ? cart.items.map( function ( item ) {
			return [ item.key || '', item.id || 0, item.quantity || 0 ];
		} ) : [];
		const signature = JSON.stringify( items );
		const status = typeof checkoutSelector.getCheckoutStatus === 'function' ? checkoutSelector.getCheckoutStatus() : '';
		if ( ! initialized && items.length ) {
			initialized = true;
			lastCart = signature;
			lastStatus = status;
			client.mint();
			return;
		}
		if ( initialized && signature !== lastCart ) {
			lastCart = signature;
			client.invalidateAndMint();
		}
		if ( initialized && status === 'idle' && lastStatus && lastStatus !== 'idle' ) {
			lastStatus = status;
			client.invalidateAndMint();
			return;
		}
		lastStatus = status;
	} );

	document.addEventListener( 'visibilitychange', function () {
		if ( document.visibilityState === 'visible' && ! client.isReady() ) {
			client.invalidateAndMint();
		}
	} );
}( window, document ) );
