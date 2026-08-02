( function ( root, factory ) {
	'use strict';
	const api = factory();
	if ( typeof module === 'object' && module.exports ) {
		module.exports = api;
	}
	root.CheckoutFirewallTurnstileCore = api;
}( typeof globalThis !== 'undefined' ? globalThis : window, function () {
	'use strict';

	const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
	let scriptPromise = null;

	function loadScript( options ) {
		if ( options.turnstile() ) {
			return Promise.resolve( options.turnstile() );
		}
		if ( scriptPromise ) {
			return scriptPromise;
		}
		scriptPromise = new Promise( function ( resolve, reject ) {
			const existing = options.document.querySelector( 'script[data-checkout-firewall-turnstile]' );
			const script = existing || options.document.createElement( 'script' );
			const ready = function () {
				const api = options.turnstile();
				if ( api ) { resolve( api ); } else { reject( new Error( 'turnstile unavailable' ) ); }
			};
			script.addEventListener( 'load', ready, { once: true } );
			script.addEventListener( 'error', function () { reject( new Error( 'turnstile unavailable' ) ); }, { once: true } );
			if ( ! existing ) {
				script.src = SCRIPT_URL;
				script.async = true;
				script.defer = true;
				script.dataset.checkoutFirewallTurnstile = '1';
				options.document.head.appendChild( script );
			}
		} ).catch( function ( error ) {
			scriptPromise = null;
			throw error;
		} );
		return scriptPromise;
	}

	function createClient( options ) {
		let generation = 0;
		let widgetId = null;
		let inflight = null;
		let inflightGeneration = 0;
		let state = 'idle';
		let submitted = false;
		const strings = options.strings || {};

		function mount() { return options.mount(); }
		function announce( message ) {
			const node = mount();
			if ( node ) {
				const status = node.querySelector( '.cf-turnstile-panel__status' );
				if ( status ) { status.textContent = message; }
			}
		}
		function paint( descriptor ) {
			const node = mount();
			if ( ! node ) { throw new Error( 'challenge mount unavailable' ); }
			node.hidden = false;
			node.replaceChildren();
			const title = options.document.createElement( 'h3' );
			title.tabIndex = -1;
			title.textContent = descriptor.title;
			const message = options.document.createElement( 'p' );
			message.textContent = descriptor.message;
			const privacy = options.document.createElement( 'p' );
			privacy.className = 'cf-turnstile-panel__privacy';
			privacy.textContent = descriptor.privacy;
			const widget = options.document.createElement( 'div' );
			widget.className = 'cf-turnstile-panel__widget';
			const status = options.document.createElement( 'p' );
			status.className = 'cf-turnstile-panel__status';
			status.setAttribute( 'aria-live', 'polite' );
			node.append( title, message, privacy, widget, status );
			title.focus();
			return widget;
		}

		function begin() {
			if ( ( inflight && inflightGeneration === generation ) || state === 'submitting' || ( options.isExpress && options.isExpress() ) ) {
				return ( inflight && inflightGeneration === generation ) ? inflight : Promise.resolve( false );
			}
			const current = ++generation;
			inflightGeneration = current;
			state = 'loading';
			submitted = false;
			const request = options.fetch( options.endpoint, { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: '{}' } )
				.then( function ( response ) { if ( ! response.ok ) { return null; } return response.json(); } )
				.then( function ( descriptor ) {
					if ( current !== generation || ! descriptor || typeof descriptor.site_key !== 'string' || typeof descriptor.state !== 'string' || typeof descriptor.cdata !== 'string' ) { return false; }
					const target = paint( descriptor );
					return loadScript( options ).then( function ( api ) {
						if ( current !== generation ) { return false; }
						if ( widgetId !== null && typeof api.remove === 'function' ) { api.remove( widgetId ); }
						widgetId = api.render( target, {
							sitekey: descriptor.site_key,
							action: descriptor.action,
							cData: descriptor.cdata,
							theme: 'light', size: 'flexible', 'response-field': false,
							'retry': 'auto', 'refresh-timeout': 'auto',
							callback: function ( token ) {
								if ( current !== generation || submitted || typeof token !== 'string' || ! token ) { return; }
								submitted = true; state = 'submitting';
								options.onSolved( token, descriptor.state );
							},
							'expired-callback': function () { if ( current === generation ) { state = 'expired'; announce( strings.expired || '' ); } },
							'error-callback': function () { if ( current === generation ) { state = 'error'; announce( strings.error || '' ); } }
						} );
						state = 'ready';
						return true;
					} );
			} ).catch( function () { if ( current === generation ) { state = 'error'; announce( strings.unavailable || '' ); } return false; } )
				.finally( function () { if ( inflightGeneration === current ) { inflight = null; } } );
			inflight = request;
			return inflight;
		}

		function reset() {
			++generation; submitted = false; state = 'idle';
			const api = options.turnstile();
			if ( api && widgetId !== null && typeof api.remove === 'function' ) { api.remove( widgetId ); }
			widgetId = null;
			const node = mount();
			if ( node ) { node.hidden = true; node.replaceChildren(); }
			if ( options.onReset ) { options.onReset(); }
		}

		return { begin: begin, reset: reset, getState: function () { return state; }, getGeneration: function () { return generation; } };
	}

	return { SCRIPT_URL: SCRIPT_URL, createClient: createClient };
} ) );
