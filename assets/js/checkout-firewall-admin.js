( function () {
	'use strict';

	const expiry = document.querySelector( '[data-cf-emergency-expiry]' );
	if ( ! expiry ) {
		return;
	}

	const timestamp = Date.parse( expiry.dataset.expiry || '' );
	const template = expiry.dataset.template || '';
	if ( ! Number.isFinite( timestamp ) ) {
		return;
	}

	const update = () => {
		const seconds = Math.max( 0, Math.floor( ( timestamp - Date.now() ) / 1000 ) );
		const hours = Math.floor( seconds / 3600 );
		const minutes = Math.floor( ( seconds % 3600 ) / 60 );
		expiry.textContent = template.replace( '%1$d', hours ).replace( '%2$d', minutes );
	};

	update();
	window.setInterval( update, 60000 );
}() );

( function () {
	'use strict';

	const selector = document.querySelector( '[data-cf-provider-selector]' );
	if ( ! selector ) {
		return;
	}

	const radios = Array.from( selector.querySelectorAll( 'input[name="challenge_provider"]' ) );
	const panels = Array.from( document.querySelectorAll( '[data-cf-provider-panel]' ) );
	const pending = selector.querySelector( '[data-cf-provider-pending]' );
	const saved = selector.dataset.savedProvider || '';
	if ( ! radios.length || ! panels.length ) {
		return;
	}

	const sync = () => {
		const selected = radios.find( ( radio ) => radio.checked );
		if ( ! selected ) {
			return;
		}
		panels.forEach( ( panel ) => {
			const visible = panel.dataset.cfProviderPanel === selected.value;
			panel.hidden = ! visible;
			panel.setAttribute( 'aria-hidden', visible ? 'false' : 'true' );
		} );
		if ( pending ) {
			pending.hidden = selected.value === saved;
		}
	};

	radios.forEach( ( radio ) => radio.addEventListener( 'change', sync ) );
	sync();
}() );
