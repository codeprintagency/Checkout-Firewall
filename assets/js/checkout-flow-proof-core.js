( function ( root, factory ) {
	'use strict';
	const api = factory();
	if ( typeof module === 'object' && module.exports ) {
		module.exports = api;
	}
	root.CheckoutFirewallFlowProofCore = api;
}( typeof globalThis !== 'undefined' ? globalThis : window, function () {
	'use strict';

	function createClient( options ) {
		const elapsedNow = typeof options.monotonicNow === 'function' ? options.monotonicNow : options.now;
		let proof = '';
		let expiresAt = 0;
		let evidenceToken = '';
		let honeypotField = '';
		let evidenceReadyAt = 0;
		let inflight = null;
		let generation = 0;
		let timer = null;
		let refreshQueued = false;

		function notify() {
			if ( typeof options.onProof === 'function' ) {
				options.onProof( proof, expiresAt, evidenceToken, honeypotField );
			}
		}

		function schedule() {
			if ( timer ) {
				options.clearTimeout( timer );
			}
			const delay = Math.max( 1000, ( expiresAt * 1000 ) - options.now() - options.refreshLeadMs );
			timer = options.setTimeout( function () {
				if ( ! options.isVisible || options.isVisible() ) {
					invalidateAndMint();
				}
			}, delay );
		}

		function mint() {
			if ( inflight ) {
				refreshQueued = true;
				return inflight;
			}
			const requestGeneration = ++generation;
			inflight = options.fetch( options.endpoint, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify( { action: options.action } ),
				cache: 'no-store'
			} ).then( function ( response ) {
				if ( ! response.ok ) {
					throw new Error( 'proof unavailable' );
				}
				return response.json();
			} ).then( function ( data ) {
				if ( requestGeneration !== generation || ! data || typeof data.proof !== 'string' || typeof data.expires_at !== 'number' ) {
					return '';
				}
				proof = data.proof;
				expiresAt = data.expires_at;
				evidenceToken = typeof data.evidence_token === 'string' ? data.evidence_token : '';
				honeypotField = typeof data.honeypot_field === 'string' ? data.honeypot_field : '';
				const waitMs = Number.isFinite( data.evidence_wait_ms ) ? Math.max( 0, Math.min( 2000, data.evidence_wait_ms ) ) : 0;
				evidenceReadyAt = evidenceToken ? elapsedNow() + waitMs : 0;
				notify();
				schedule();
				return proof;
			} ).catch( function () {
				if ( requestGeneration === generation ) {
					proof = '';
					expiresAt = 0;
					evidenceToken = '';
					honeypotField = '';
					evidenceReadyAt = 0;
					notify();
				}
				return '';
			} ).finally( function () {
				inflight = null;
				if ( refreshQueued ) {
					refreshQueued = false;
					mint();
				}
			} );
			return inflight;
		}

		function invalidate() {
			++generation;
			proof = '';
			expiresAt = 0;
			evidenceToken = '';
			honeypotField = '';
			evidenceReadyAt = 0;
			if ( timer ) {
				options.clearTimeout( timer );
				timer = null;
			}
			notify();
		}

		function invalidateAndMint() {
			invalidate();
			return mint();
		}

		function waitUntilEvidenceReady() {
			if ( inflight ) {
				return inflight.then( waitUntilEvidenceReady );
			}
			const current = generation;
			const delay = evidenceToken ? Math.max( 0, Math.min( 2000, evidenceReadyAt - elapsedNow() ) ) : 0;
			if ( 0 === delay ) {
				return Promise.resolve();
			}
			return new Promise( function ( resolve ) { options.setTimeout( resolve, delay ); } ).then( function () {
				return current === generation ? undefined : waitUntilEvidenceReady();
			} );
		}

		return {
			mint: mint,
			invalidate: invalidate,
			invalidateAndMint: invalidateAndMint,
			waitUntilEvidenceReady: waitUntilEvidenceReady,
			getProof: function () { return proof; },
			isReady: function () { return proof !== '' && ( expiresAt * 1000 ) > options.now(); }
		};
	}

	return { createClient: createClient };
} ) );
