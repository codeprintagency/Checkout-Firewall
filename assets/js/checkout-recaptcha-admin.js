( function ( window, document ) {
	'use strict';
	const form = document.querySelector( '.cf-recaptcha-health' );
	if ( ! form ) { return; }
	const button = form.querySelector( '[data-cf-recaptcha-verify]' );
	const token = form.querySelector( '[name="health_token"]' );
	const widget = form.querySelector( '.cf-health__widget' );
	if ( ! button || ! token || ! widget ) { return; }
	const fail = function ( message ) {
		token.value = '';
		button.disabled = true;
		widget.textContent = message;
	};
	const script = document.createElement( 'script' );
	script.src = 'https://www.google.com/recaptcha/api.js?render=explicit'; script.async = true; script.defer = true;
	script.addEventListener( 'load', function () {
		if ( ! window.grecaptcha || 'function' !== typeof window.grecaptcha.render ) { fail( form.dataset.loadError || '' ); return; }
		try {
			window.grecaptcha.render( widget, { sitekey: form.dataset.siteKey, callback: function ( value ) { token.value = value; button.disabled = false; }, 'expired-callback': function () { token.value = ''; button.disabled = true; }, 'error-callback': function () { fail( form.dataset.widgetError || '' ); } } );
		} catch ( error ) {
			fail( form.dataset.widgetError || '' );
		}
	} );
	script.addEventListener( 'error', function () { fail( form.dataset.loadError || '' ); } );
	button.addEventListener( 'click', function () { if ( token.value ) { form.submit(); } } );
	document.head.appendChild( script );
}( window, document ) );
