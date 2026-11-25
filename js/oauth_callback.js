/*
 * Delivery of the answer of an OAuth provider by the callback pages getToken.html, getTokenGoogle.html and
 * getTokenLinkedIn.html to the window that opened the sign-in popup.
 *
 * The answer holds an access token, an id_token or an authorization code: it is posted to each allowed origin below,
 * that origin being the target origin of the message (the browser delivers a message only to a window of its target
 * origin).
 *
 * The allowed origins are:
 * - the origin of this page: the applications served by this Convertigo server (OAuth action with its default callback);
 * - the origins of the symbol lib_oauth.callback.allowed_origins, read by the getCallbackOrigins sequence: the
 *   applications of other servers that use the callback of this server (comma or space separated, scheme, host and
 *   port only, as https://forms.example.com or http://localhost:18080; '*', paths and patterns are ignored).
 *
 * This file is loaded by the callback pages in the browser (it is not a server side script).
 */
(function (global) {
	"use strict";

	var ENTRY = /^https?:\/\/(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?\/?$/;

	// The origin of an entry of the symbol (scheme, host and port, normalized), or null when it is not one.
	function originOf(entry) {
		entry = ("" + entry).trim();
		if (!ENTRY.test(entry)) {
			return null;
		}
		try {
			var origin = new URL(entry).origin;
			return /^https?:\/\//.test(origin) ? origin : null;
		} catch (e) {
			return null;
		}
	}

	// The origins of the value of the symbol, without duplicates; invalid entries are ignored.
	function allowedOrigins(value) {
		var origins = [];
		("" + (typeof value === "string" ? value : "")).split(/[\s,;]+/).forEach(function (entry) {
			var origin = entry ? originOf(entry) : null;
			if (origin && origins.indexOf(origin) === -1) {
				origins.push(origin);
			}
		});
		return origins;
	}

	// The target origins of the answer: the origin of this page, then the allowed origins of the symbol.
	function targets(ownOrigin, value) {
		var list = [];
		var own = originOf(ownOrigin);
		if (own) {
			list.push(own);
		}
		allowedOrigins(value).forEach(function (origin) {
			if (list.indexOf(origin) === -1) {
				list.push(origin);
			}
		});
		return list;
	}

	// The value of the symbol, from the getCallbackOrigins sequence of this project ("" when it cannot be read). The call
	// sends no cookie (an existing session of the user on this server is neither used nor removed) and removes the
	// session it creates.
	function readSymbol(timeout) {
		if (typeof global.fetch !== "function") {
			return Promise.resolve("");
		}
		var controller = typeof global.AbortController === "function" ? new global.AbortController() : null;
		var timer = controller ? global.setTimeout(function () { controller.abort(); }, timeout || 10000) : null;
		return global.fetch(".json?__sequence=getCallbackOrigins&__removeSession=true", {
			method: "GET",
			credentials: "omit",
			cache: "no-store",
			signal: controller ? controller.signal : undefined
		}).then(function (response) {
			return response.ok ? response.json() : {};
		}).then(function (data) {
			var value = data ? data.origins : undefined;
			if (value === undefined && data && data.document) {
				value = data.document.origins;
			}
			return typeof value === "string" ? value : "";
		})["catch"](function () {
			return "";
		}).then(function (value) {
			if (timer) {
				global.clearTimeout(timer);
			}
			return value;
		});
	}

	// Posts the answer to the opener for each allowed origin (the browser drops the messages whose target origin is not
	// the origin of the opener), then closes the popup. Resolves the list of target origins.
	function deliver(answer, options) {
		options = options || {};
		var opener = global.opener;
		if (!opener) {
			return Promise.resolve([]);
		}
		return readSymbol(options.timeout).then(function (value) {
			var list = targets(global.location.origin, value);
			list.forEach(function (origin) {
				try {
					opener.postMessage(answer, origin);
				} catch (e) {
					// closed opener: nothing to deliver
				}
			});
			if (options.close !== false) {
				global.close();
			}
			return list;
		});
	}

	global.c8oOAuthCallback = {
		originOf: originOf,
		allowedOrigins: allowedOrigins,
		targets: targets,
		readSymbol: readSymbol,
		deliver: deliver
	};
})(this);
