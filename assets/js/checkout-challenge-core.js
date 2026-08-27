( function ( root, factory ) {
	'use strict';
	const api = factory();
	if ( typeof module === 'object' && module.exports ) { module.exports = api; }
	root.CheckoutFirewallChallengeCore = api;
}( typeof globalThis !== 'undefined' ? globalThis : window, function () {
	'use strict';

	const global = typeof globalThis !== 'undefined' ? globalThis : window;
	const TURNSTILE_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
	const RECAPTCHA_URL = 'https://www.google.com/recaptcha/api.js?render=explicit';
	const loaders = {};

	function loadScript( options, key, url, test, module ) {
		if ( test() ) { return Promise.resolve( test() ); }
		if ( loaders[ key ] ) { return loaders[ key ]; }
		loaders[ key ] = new Promise( function ( resolve, reject ) {
			const selector = 'script[data-checkout-firewall-provider="' + key + '"]';
			const existing = options.document.querySelector( selector );
			const script = existing || options.document.createElement( 'script' );
			const ready = function () {
				const api = test();
				if ( api ) { resolve( api ); } else { reject( new Error( key + ' unavailable' ) ); }
			};
			script.addEventListener( 'load', ready, { once: true } );
			script.addEventListener( 'error', function () { reject( new Error( key + ' unavailable' ) ); }, { once: true } );
			if ( ! existing ) {
				script.src = url;
				script.async = true;
				script.defer = true;
				if ( module ) { script.type = 'module'; }
				script.dataset.checkoutFirewallProvider = key;
				options.document.head.appendChild( script );
			}
		} ).catch( function ( error ) { loaders[ key ] = null; throw error; } );
		return loaders[ key ];
	}

	function loadStyle( options, url ) {
		if ( ! url || options.document.querySelector( 'link[data-checkout-firewall-altcha]' ) ) { return; }
		const link = options.document.createElement( 'link' );
		link.rel = 'stylesheet'; link.href = url; link.dataset.checkoutFirewallAltcha = '1';
		options.document.head.appendChild( link );
	}

	function createClient( options ) {
		let generation = 0;
		let widget = null;
		let provider = '';
		let inflight = null;
		let state = 'idle';
		let submitted = false;
		const strings = options.strings || {};

		function mount() { return options.mount(); }
		function announce( message ) {
			const node = mount();
			const status = node && node.querySelector( '.cf-challenge-panel__status' );
			if ( status ) { status.textContent = message; }
		}
		function offerRetry() {
			const node = mount();
			if ( ! node || node.querySelector( '[data-checkout-firewall-retry]' ) ) { return; }
			const button = options.document.createElement( 'button' );
			button.type = 'button';
			button.className = 'cf-challenge-panel__retry';
			button.dataset.checkoutFirewallRetry = '1';
			button.textContent = strings.retry || 'Try security check again';
			button.addEventListener( 'click', function () {
				button.disabled = true;
				reset();
				return begin();
			} );
			node.append( button );
		}
		function failed( message ) {
			state = 'error';
			const node = mount();
			if ( node ) {
				node.hidden = false;
				if ( ! node.querySelector( '.cf-challenge-panel__status' ) ) {
					const status = options.document.createElement( 'p' );
					status.className = 'cf-challenge-panel__status';
					status.setAttribute( 'aria-live', 'polite' );
					node.append( status );
				}
			}
			announce( message );
			offerRetry();
		}
		function paint( descriptor ) {
			const node = mount();
			if ( ! node ) { throw new Error( 'challenge mount unavailable' ); }
			node.hidden = false; node.replaceChildren();
			const title = options.document.createElement( 'h3' ); title.tabIndex = -1; title.textContent = descriptor.title;
			const message = options.document.createElement( 'p' ); message.textContent = descriptor.message;
			const privacy = options.document.createElement( 'p' ); privacy.className = 'cf-challenge-panel__privacy'; privacy.textContent = descriptor.privacy;
			const target = options.document.createElement( 'div' ); target.className = 'cf-challenge-panel__widget';
			const status = options.document.createElement( 'p' ); status.className = 'cf-challenge-panel__status'; status.setAttribute( 'aria-live', 'polite' );
			node.append( title, message, privacy, target, status ); title.focus();
			return target;
		}
		function solved( token, descriptor, current ) {
			if ( current !== generation || submitted || typeof token !== 'string' || ! token ) { return; }
			submitted = true; state = options.autoSubmit === false ? 'verified' : 'submitting'; options.onSolved( token, descriptor.state );
		}
		function renderLocal( descriptor, target, current ) {
			loadStyle( options, options.localStyle );
			return loadScript( options, 'local', options.localScript, function () { return global.$altcha && global.customElements && global.customElements.get( 'altcha-widget' ) ? global.$altcha : null; }, true ).then( function () {
				if ( current !== generation ) { return false; }
				if ( ! global.$altcha.algorithms.has( 'PBKDF2/SHA-256' ) ) {
					global.$altcha.algorithms.set( 'PBKDF2/SHA-256', function () { return new Worker( options.localWorker, { type: 'module' } ); } );
				}
				const language = typeof options.language === 'string' && options.language ? options.language : 'en';
				global.$altcha.i18n.set( language, {
					ariaLinkLabel: strings.localAria || 'Visit ALTCHA.org', enterCode: strings.localCode || 'Enter code', enterCodeAria: strings.localCodeAria || 'Enter the security code',
					error: strings.error || 'Verification failed.', expired: strings.expired || 'Verification expired.', footer: strings.localFooter || 'Protected by ALTCHA',
					getAudioChallenge: strings.localAudio || 'Get an audio challenge', label: strings.localLabel || 'Verify this browser', loading: strings.localLoading || 'Loading…',
					reload: strings.localReload || 'Reload', verify: strings.localVerify || 'Verify', verificationRequired: strings.localRequired || 'Verification required',
					verified: strings.localVerified || 'Verified', verifying: strings.verifying || 'Verifying…', waitAlert: strings.localWait || 'Please wait while your browser is verified.'
				} );
				widget = options.document.createElement( 'altcha-widget' );
				widget.addEventListener( 'verified', function ( event ) { solved( event.detail && event.detail.payload, descriptor, current ); } );
				widget.addEventListener( 'expired', function () { if ( current === generation ) { failed( strings.expired || '' ); } } );
				widget.addEventListener( 'statechange', function ( event ) { if ( current === generation && event.detail && event.detail.state === 'error' ) { failed( strings.error || '' ); } } );
				target.appendChild( widget );
				widget.configure( { challenge: descriptor.challenge, auto: 'onload', display: 'standard', type: 'native', language: language, workers: 1, timeout: 120000, minDuration: 500, humanInteractionSignature: false, hideFooter: false } );
				state = 'ready'; return true;
			} );
		}
		function renderTurnstile( descriptor, target, current ) {
			return loadScript( options, 'turnstile', TURNSTILE_URL, function () { return global.turnstile || null; }, false ).then( function ( api ) {
				if ( current !== generation ) { return false; }
				widget = api.render( target, { sitekey: descriptor.site_key, action: descriptor.action, cData: descriptor.cdata, theme: 'light', size: 'flexible', 'response-field': false, callback: function ( token ) { solved( token, descriptor, current ); }, 'expired-callback': function () { if ( current === generation ) { failed( strings.expired || '' ); } }, 'error-callback': function () { if ( current === generation ) { failed( strings.error || '' ); } } } );
				state = 'ready'; return true;
			} );
		}
		function renderRecaptcha( descriptor, target, current ) {
			return loadScript( options, 'recaptcha', RECAPTCHA_URL, function () { return global.grecaptcha && typeof global.grecaptcha.render === 'function' ? global.grecaptcha : null; }, false ).then( function ( api ) {
				if ( current !== generation ) { return false; }
				widget = api.render( target, { sitekey: descriptor.site_key, callback: function ( token ) { solved( token, descriptor, current ); }, 'expired-callback': function () { if ( current === generation ) { failed( strings.expired || '' ); } }, 'error-callback': function () { if ( current === generation ) { failed( strings.error || '' ); } } } );
				state = 'ready'; return true;
			} );
		}
		function begin() {
			if ( inflight || state === 'submitting' || ( options.isExpress && options.isExpress() ) ) { return inflight || Promise.resolve( false ); }
			const current = ++generation; state = 'loading'; submitted = false;
			const body = options.preflight ? { intent: 'preflight', surface: options.surface || 'classic' } : {};
			inflight = options.fetch( options.endpoint, { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify( body ) } )
				.then( function ( response ) { if ( response.status === 404 ) { return null; } if ( ! response.ok ) { throw new Error( 'challenge descriptor unavailable' ); } return response.json(); } )
				.then( function ( descriptor ) {
					if ( current !== generation ) { return false; }
					if ( descriptor === null ) { state = 'idle'; return false; }
					if ( ! descriptor || typeof descriptor.provider !== 'string' || typeof descriptor.state !== 'string' ) { throw new Error( 'invalid challenge descriptor' ); }
					provider = descriptor.provider; const target = paint( descriptor ); announce( strings.verifying || '' );
					if ( provider === 'local' && descriptor.challenge ) { return renderLocal( descriptor, target, current ); }
					if ( provider === 'turnstile' && descriptor.site_key && descriptor.cdata ) { return renderTurnstile( descriptor, target, current ); }
					if ( provider === 'recaptcha' && descriptor.site_key ) { return renderRecaptcha( descriptor, target, current ); }
					throw new Error( 'unsupported challenge provider' );
				} ).catch( function () { if ( current === generation ) { failed( strings.unavailable || '' ); } return false; } )
				.finally( function () { inflight = null; } );
			return inflight;
		}
		function reset() {
			++generation; submitted = false; state = 'idle';
			if ( provider === 'turnstile' && global.turnstile && widget !== null && typeof global.turnstile.remove === 'function' ) { global.turnstile.remove( widget ); }
			if ( provider === 'recaptcha' && global.grecaptcha && widget !== null && typeof global.grecaptcha.reset === 'function' ) { global.grecaptcha.reset( widget ); }
			if ( provider === 'local' && widget && typeof widget.reset === 'function' ) { widget.reset(); }
			widget = null; provider = ''; const node = mount(); if ( node ) { node.hidden = true; node.replaceChildren(); }
			if ( options.onReset ) { options.onReset(); }
		}
		return { begin: begin, reset: reset, getState: function () { return state; } };
	}

	return { createClient: createClient, TURNSTILE_URL: TURNSTILE_URL, RECAPTCHA_URL: RECAPTCHA_URL };
} ) );
