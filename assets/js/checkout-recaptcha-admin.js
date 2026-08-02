( function ( window, document ) {
	'use strict';
	const form = document.querySelector( '.cf-recaptcha-health' );
	if ( ! form ) { return; }
	const button = form.querySelector( '[data-cf-recaptcha-verify]' );
	const token = form.querySelector( '[name="health_token"]' );
	const script = document.createElement( 'script' );
	script.src = 'https://www.google.com/recaptcha/api.js?render=explicit'; script.async = true; script.defer = true;
	script.addEventListener( 'load', function () { window.grecaptcha.render( form.querySelector( '.cf-health__widget' ), { sitekey: form.dataset.siteKey, callback: function ( value ) { token.value = value; button.disabled = false; }, 'expired-callback': function () { token.value = ''; button.disabled = true; }, 'error-callback': function () { token.value = ''; button.disabled = true; } } ); } );
	button.addEventListener( 'click', function () { if ( token.value ) { form.submit(); } } );
	document.head.appendChild( script );
}( window, document ) );
