( function ( window, document ) {
	'use strict';
	const form = document.querySelector( '.cf-health' );
	if ( ! form ) { return; }
	const button = form.querySelector( '[data-cf-verify]' );
	const token = form.querySelector( '[name="health_token"]' );
	const script = document.createElement( 'script' );
	script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
	script.async = true; script.defer = true;
	script.addEventListener( 'load', function () {
		window.turnstile.render( form.querySelector( '.cf-health__widget' ), { sitekey: form.dataset.siteKey, action: form.dataset.action, cData: form.dataset.cdata, theme: 'light', size: 'flexible', 'response-field': false, callback: function ( value ) { token.value = value; button.disabled = false; }, 'expired-callback': function () { token.value = ''; button.disabled = true; } } );
	} );
	button.addEventListener( 'click', function () { if ( token.value ) { form.submit(); } } );
	document.head.appendChild( script );
}( window, document ) );
