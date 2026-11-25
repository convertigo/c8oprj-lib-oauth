/*
 * lib_OAuth - scopes requested by the OpenID sign-in
 *
 * Loaded by GetOAuthCredentials with include("js/openid_scope.js"). The symbol lib_oauth.openid.scope lists the
 * scopes, separated by spaces or commas. "openid" is always requested. When the symbol is empty, the scopes of the
 * earlier versions are requested: "openid profile email". An invalid value (a scope with a character that RFC 6749
 * does not allow, more than 50 scopes, more than 2048 characters) is ignored with a warning and the default is used.
 *
 * The OAuth action of the Mobile Builder adds the scope to the authorization URL as it is: the value it receives
 * (OpenIDScope of GetOAuthCredentials) is therefore URL encoded.
 *
 * Written in ES5 for the Convertigo Rhino engine; resolve() is unit tested under Node.
 */
var libOAuthOpenIdScope = (function () {
	var SYMBOL = "lib_oauth.openid.scope";
	var DEFAULT_SCOPES = ["openid", "profile", "email"];
	var MAX_LENGTH = 2048;
	var MAX_SCOPES = 50;
	// RFC 6749 3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ), the comma being a separator here
	var SCOPE_TOKEN = /^[\x21\x23-\x2B\x2D-\x5B\x5D-\x7E]+$/;

	function encode(scopes) {
		var parts = [];
		for (var i = 0; i < scopes.length; i++) {
			parts.push(encodeURIComponent(scopes[i]));
		}
		return parts.join("%20");
	}

	function result(scopes, source, warning) {
		return { scopes: scopes, scope: scopes.join(" "), encoded: encode(scopes), source: source, warning: warning || "" };
	}

	function fallback(warning) {
		return result(DEFAULT_SCOPES.slice(0), "default", warning);
	}

	/**
	 * Scopes of a value of the symbol: { scopes, scope (space separated), encoded (for the authorization URL),
	 * source: "symbol" or "default", warning }.
	 */
	function resolve(raw) {
		var value = raw == null ? "" : String(raw).replace(/^\s+|\s+$/g, "");
		if (value.length == 0 || value.indexOf("${") != -1) {
			return fallback("");
		}
		if (value.length > MAX_LENGTH) {
			return fallback("symbol " + SYMBOL + " is too long, the default scopes are requested");
		}
		var tokens = value.split(/[\s,]+/);
		var scopes = ["openid"];
		for (var i = 0; i < tokens.length; i++) {
			var token = tokens[i];
			if (token.length == 0) {
				continue;
			}
			if (!SCOPE_TOKEN.test(token)) {
				return fallback("symbol " + SYMBOL + " holds an invalid scope, the default scopes are requested");
			}
			var known = false;
			for (var j = 0; j < scopes.length; j++) {
				if (scopes[j] === token) {
					known = true;
				}
			}
			if (!known) {
				scopes.push(token);
			}
		}
		if (scopes.length > MAX_SCOPES) {
			return fallback("symbol " + SYMBOL + " holds more than " + MAX_SCOPES + " scopes, the default scopes are requested");
		}
		return result(scopes, "symbol", "");
	}

	// Value of the symbol, compiled like a ${name} reference of a bean property (a %ENV% value is resolved).
	function symbolValue() {
		var symbols = com.twinsoft.convertigo.engine.Engine.theApp.databaseObjectsManager;
		var value = symbols.symbolsGetValue(SYMBOL);
		if (value == null) {
			return "";
		}
		try {
			value = symbols.getCompiledValue("$" + "{" + SYMBOL + "}");
		} catch (e) {
			// keep the raw value when it refers to an undefined symbol
		}
		return String(value);
	}

	return {
		SYMBOL: SYMBOL,
		DEFAULT_SCOPE: DEFAULT_SCOPES.join(" "),
		resolve: resolve,
		fromSymbol: function () {
			return resolve(symbolValue());
		}
	};
})();
