/*
 * lib_OAuth - verification of the JWT returned by the identity providers
 *
 * Loaded by the login sequences with include("js/jwt_verify.js"). A token is
 * trusted only after its signature (asymmetric algorithms only, key taken from
 * the provider JWKS by kid), its issuer, its audience and its validity window
 * (exp / nbf / iat, 5 minutes of clock skew) have been checked. The verify*
 * functions never throw: they return { ok: true, claims: {...} } or
 * { ok: false, error: "..." } and callers must refuse the login on !ok.
 *
 * openIdGroups reads the groups of an OpenID user (claim of lib_oauth.openid.groups_claim) from verified sources only:
 * a verified id_token, the verified access token or introspection response, the userinfo endpoint of the provider.
 *
 * Discovery documents and JWKS are fetched over HTTPS and cached in the
 * servlet context (JWKS: 1 hour, discovery: 6 hours). An unknown kid forces a
 * JWKS refresh, at most once a minute per provider.
 *
 * Written in ES5 for the Convertigo Rhino engine; the Java dependent parts are
 * isolated in javaPlatform() so the logic can be unit tested under Node.
 */
var libOAuthJwt = (function () {
	var CLOCK_SKEW_SECONDS = 300;
	var JWKS_TTL_MS = 3600 * 1000;
	var DISCOVERY_TTL_MS = 6 * 3600 * 1000;
	var MIN_REFRESH_MS = 60 * 1000;
	var MAX_TOKEN_LENGTH = 16384;
	var CACHE_ATTRIBUTE = "lib_OAuth.jwt_verify.cache";

	var GOOGLE_DISCOVERY = "https://accounts.google.com/.well-known/openid-configuration";
	var GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
	var MICROSOFT_AUTHORITY = "https://login.microsoftonline.com/";
	var GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

	// Only asymmetric algorithms: "none" and HS* are always refused.
	var ALGORITHMS = {
		RS256: { kty: "RSA", java: "SHA256withRSA" },
		RS384: { kty: "RSA", java: "SHA384withRSA" },
		RS512: { kty: "RSA", java: "SHA512withRSA" },
		ES256: { kty: "EC", crv: "P-256", java: "SHA256withECDSAinP1363Format" },
		ES384: { kty: "EC", crv: "P-384", java: "SHA384withECDSAinP1363Format" },
		ES512: { kty: "EC", crv: "P-521", java: "SHA512withECDSAinP1363Format" }
	};
	var CURVES = { "P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1" };
	var ASYMMETRIC = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"];

	function VerificationError(message) {
		this.message = message;
	}

	function fail(message) {
		throw new VerificationError(message);
	}

	function isString(value) {
		return typeof value === "string" || value instanceof String;
	}

	function nonEmpty(value) {
		return value != null && isString(value) && String(value).length > 0;
	}

	function isArray(value) {
		// realm independent (Rhino JSON results may come from another scope)
		return Object.prototype.toString.call(value) === "[object Array]";
	}

	function contains(list, value) {
		for (var i = 0; i < list.length; i++) {
			if (list[i] === value) {
				return true;
			}
		}
		return false;
	}

	/* ---------------------------------------------------------------- Java */

	function javaPlatform() {
		function bytes(size) {
			return java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, size);
		}

		function cacheMap() {
			try {
				var servletContext = com.twinsoft.convertigo.engine.Engine.getServletContext();
				if (servletContext == null) {
					return null;
				}
				var map = servletContext.getAttribute(CACHE_ATTRIBUTE);
				if (map == null) {
					servletContext.setAttribute(CACHE_ATTRIBUTE, new java.util.concurrent.ConcurrentHashMap());
					map = servletContext.getAttribute(CACHE_ATTRIBUTE);
				}
				return map;
			} catch (e) {
				return null;
			}
		}

		function publicKey(jwk) {
			var decoder = java.util.Base64.getUrlDecoder();
			if (jwk.kty === "RSA") {
				var modulus = new java.math.BigInteger(1, decoder.decode(String(jwk.n)));
				if (modulus.bitLength() < 2048) {
					fail("RSA key too short");
				}
				var exponent = new java.math.BigInteger(1, decoder.decode(String(jwk.e)));
				return java.security.KeyFactory.getInstance("RSA").generatePublic(new java.security.spec.RSAPublicKeySpec(modulus, exponent));
			}
			var parameters = java.security.AlgorithmParameters.getInstance("EC");
			parameters.init(new java.security.spec.ECGenParameterSpec(CURVES[jwk.crv]));
			var spec = parameters.getParameterSpec(java.lang.Class.forName("java.security.spec.ECParameterSpec"));
			var point = new java.security.spec.ECPoint(
				new java.math.BigInteger(1, decoder.decode(String(jwk.x))),
				new java.math.BigInteger(1, decoder.decode(String(jwk.y))));
			return java.security.KeyFactory.getInstance("EC").generatePublic(new java.security.spec.ECPublicKeySpec(point, spec));
		}

		// HTTPS GET of a JSON document, no redirect, 1 MB at most. The Authorization header is never part of an error.
		function get(url, authorization) {
			// ProxySelector and Authenticator are installed by the engine ProxyManager.
			var connection = new java.net.URL(url).openConnection();
			connection.setConnectTimeout(5000);
			connection.setReadTimeout(10000);
			connection.setInstanceFollowRedirects(false);
			connection.setUseCaches(false);
			connection.setRequestProperty("Accept", "application/json");
			if (authorization != null) {
				connection.setRequestProperty("Authorization", authorization);
			}
			try {
				var status = connection.getResponseCode();
				if (status != 200) {
					fail("HTTP " + status + " from " + url);
				}
				var input = connection.getInputStream();
				var output = new java.io.ByteArrayOutputStream();
				var buffer = bytes(8192);
				var read;
				while ((read = input.read(buffer)) != -1) {
					output.write(buffer, 0, read);
					if (output.size() > 1048576) {
						fail("response too large from " + url);
					}
				}
				input.close();
				return String(new java.lang.String(output.toByteArray(), "UTF-8"));
			} finally {
				connection.disconnect();
			}
		}

		return {
			now: function () {
				return Number(java.lang.System.currentTimeMillis());
			},
			decodeBase64Url: function (text) {
				return java.util.Base64.getUrlDecoder().decode(String(text));
			},
			utf8: function (data) {
				return String(new java.lang.String(data, "UTF-8"));
			},
			verifySignature: function (alg, jwk, signingInput, signature) {
				var verifier = java.security.Signature.getInstance(ALGORITHMS[alg].java);
				verifier.initVerify(publicKey(jwk));
				verifier.update(new java.lang.String(signingInput).getBytes("US-ASCII"));
				return verifier.verify(signature) == true;
			},
			// OpenID Connect at_hash: base64url of the left half of the hash of the ASCII access token
			accessTokenHash: function (alg, accessToken) {
				var digest = java.security.MessageDigest.getInstance("SHA-" + alg.substring(2)).digest(new java.lang.String(accessToken).getBytes("US-ASCII"));
				return String(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.Arrays.copyOf(digest, digest.length / 2)));
			},
			fetch: function (url) {
				return get(url, null);
			},
			// GET of the OpenID userinfo endpoint with the access token of the user (never logged, never cached).
			fetchWithBearer: function (url, accessToken) {
				return get(url, "Bearer " + accessToken);
			},
			cacheGet: function (key) {
				var map = cacheMap();
				var value = map == null ? null : map.get(key);
				return value == null ? null : String(value);
			},
			cachePut: function (key, value) {
				var map = cacheMap();
				if (map != null) {
					map.put(key, new java.lang.String(value));
				}
			},
			symbol: function (name) {
				var symbols = com.twinsoft.convertigo.engine.Engine.theApp.databaseObjectsManager;
				var value = symbols.symbolsGetValue(name);
				if (value == null) {
					return "";
				}
				try {
					// Compiled as a ${name} reference, like the former bean properties: a %ENV% value is resolved.
					value = symbols.getCompiledValue("${" + name + "}");
				} catch (e) {
					// keep the raw value when it refers to an undefined symbol
				}
				return String(value).trim();
			}
		};
	}

	var api = {
		CLOCK_SKEW_SECONDS: CLOCK_SKEW_SECONDS,
		ASYMMETRIC: ASYMMETRIC,
		platform: null
	};

	function platform() {
		if (api.platform == null) {
			api.platform = javaPlatform();
		}
		return api.platform;
	}

	/* --------------------------------------------------------------- utils */

	function configured(name) {
		var value = platform().symbol(name);
		if (!nonEmpty(value) || value.indexOf("${") != -1) {
			fail("symbol " + name + " is not configured");
		}
		return value;
	}

	function optionalSymbol(name) {
		var value;
		try {
			value = platform().symbol(name);
		} catch (e) {
			return "";
		}
		return nonEmpty(value) && value.indexOf("${") == -1 ? value : "";
	}

	// https everywhere, plain http only for a loopback provider (local IdP for development).
	function isAllowedUrl(url) {
		var match = /^(https?):\/\/([^\/?#@]+)(?:[\/?][^#]*)?$/i.exec(isString(url) ? String(url) : "");
		if (match == null) {
			return false;
		}
		if (match[1].toLowerCase() === "https") {
			return true;
		}
		var host = match[2].toLowerCase().replace(/:\d+$/, "");
		return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
	}

	function parseJson(text, what) {
		var value;
		try {
			value = JSON.parse(text);
		} catch (e) {
			fail(what + " is not valid JSON");
		}
		if (value == null || typeof value !== "object" || isArray(value)) {
			fail(what + " is not a JSON object");
		}
		return value;
	}

	function decodeSegment(segment, what) {
		var text;
		try {
			text = platform().utf8(platform().decodeBase64Url(segment));
		} catch (e) {
			fail(what + " is not valid base64url");
		}
		return parseJson(text, what);
	}

	function parse(token) {
		if (!isString(token)) {
			fail("token is missing");
		}
		token = String(token);
		if (token.length > MAX_TOKEN_LENGTH || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
			fail("token is not a signed compact JWT");
		}
		var parts = token.split(".");
		var header = decodeSegment(parts[0], "JWT header");
		var claims = decodeSegment(parts[1], "JWT payload");
		var signature;
		try {
			signature = platform().decodeBase64Url(parts[2]);
		} catch (e) {
			fail("JWT signature is not valid base64url");
		}
		return {
			header: header,
			claims: claims,
			signingInput: parts[0] + "." + parts[1],
			signature: signature
		};
	}

	/* ------------------------------------------------------ remote documents */

	function cachedJson(key, url, ttl, force) {
		var now = platform().now();
		var cached = platform().cacheGet(key);
		if (cached != null) {
			var separator = cached.indexOf("|");
			var fetchedAt = Number(cached.substring(0, separator));
			var age = now - fetchedAt;
			if (age >= 0 && (force ? age < MIN_REFRESH_MS : age < ttl)) {
				return { json: parseJson(cached.substring(separator + 1), url), fresh: false };
			}
		}
		if (!isAllowedUrl(url)) {
			fail("refusing to fetch " + url);
		}
		var text;
		try {
			text = String(platform().fetch(url));
		} catch (e) {
			fail("cannot fetch " + url + ": " + (e && e.message ? e.message : e));
		}
		var json = parseJson(text, url);
		platform().cachePut(key, now + "|" + text);
		return { json: json, fresh: true };
	}

	function discovery(url) {
		var config = cachedJson("discovery:" + url, url, DISCOVERY_TTL_MS, false).json;
		if (!nonEmpty(config.issuer)) {
			fail("discovery document without issuer");
		}
		if (!isAllowedUrl(config.jwks_uri)) {
			fail("discovery document without a usable jwks_uri");
		}
		return config;
	}

	function jwks(uri, force) {
		var result = cachedJson("jwks:" + uri, uri, JWKS_TTL_MS, force);
		var keys = result.json.keys;
		if (!isArray(keys)) {
			fail("JWKS without keys");
		}
		return { keys: keys, fresh: result.fresh };
	}

	function candidateKeys(keys, header) {
		var spec = ALGORITHMS[header.alg];
		var selected = [];
		for (var i = 0; i < keys.length; i++) {
			var key = keys[i];
			if (key == null || typeof key !== "object" || key.kty !== spec.kty) {
				continue;
			}
			if (header.kid != null && key.kid !== header.kid) {
				continue;
			}
			if (key.use != null && key.use !== "sig") {
				continue;
			}
			if (key.alg != null && key.alg !== header.alg) {
				continue;
			}
			if (isArray(key.key_ops) && !contains(key.key_ops, "verify")) {
				continue;
			}
			if (spec.kty === "RSA" ? !(nonEmpty(key.n) && nonEmpty(key.e)) : !(key.crv === spec.crv && nonEmpty(key.x) && nonEmpty(key.y))) {
				continue;
			}
			selected.push(key);
		}
		return selected;
	}

	function checkSignature(parsed, jwksUri, algorithms) {
		var header = parsed.header;
		if (!nonEmpty(header.alg) || !contains(algorithms, String(header.alg)) || !ALGORITHMS.hasOwnProperty(String(header.alg))) {
			fail("JWT algorithm " + header.alg + " is not accepted");
		}
		if (header.crit != null) {
			fail("JWT critical header parameters are not supported");
		}
		if (header.kid != null && !isString(header.kid)) {
			fail("JWT kid is invalid");
		}
		var set = jwks(jwksUri, false);
		var keys = candidateKeys(set.keys, header);
		if (keys.length == 0 && !set.fresh) {
			// unknown kid: the provider may have rotated its keys
			keys = candidateKeys(jwks(jwksUri, true).keys, header);
		}
		if (keys.length == 0) {
			fail("no signing key matches the JWT");
		}
		for (var i = 0; i < keys.length; i++) {
			try {
				if (platform().verifySignature(String(header.alg), keys[i], parsed.signingInput, parsed.signature)) {
					return keys[i];
				}
			} catch (e) {
				// unusable key or malformed signature: try the next candidate
			}
		}
		fail("JWT signature is invalid");
	}

	/* --------------------------------------------------------------- claims */

	// Lists of strings: a JSON string or array, or the {item: [...]} shape of an untyped XML conversion.
	function stringList(value, what) {
		if (value == null || value === "") {
			return [];
		}
		if (isString(value)) {
			return [String(value)];
		}
		if (!isArray(value) && typeof value === "object" && value.item != null) {
			return stringList(value.item, what);
		}
		if (isArray(value)) {
			var list = [];
			for (var i = 0; i < value.length; i++) {
				if (!isString(value[i])) {
					fail(what + " is invalid");
				}
				list.push(String(value[i]));
			}
			return list;
		}
		fail(what + " is invalid");
	}

	function audiences(claims) {
		return stringList(claims.aud, "JWT aud");
	}

	function checkTime(claims, requireIat) {
		var now = Math.floor(platform().now() / 1000);
		if (typeof claims.exp !== "number" || !isFinite(claims.exp)) {
			fail("JWT exp is missing");
		}
		if (now >= claims.exp + CLOCK_SKEW_SECONDS) {
			fail("JWT is expired");
		}
		if (claims.nbf != null && (typeof claims.nbf !== "number" || claims.nbf > now + CLOCK_SKEW_SECONDS)) {
			fail("JWT is not valid yet");
		}
		if (claims.iat == null ? requireIat : (typeof claims.iat !== "number" || claims.iat > now + CLOCK_SKEW_SECONDS)) {
			fail("JWT iat is missing or in the future");
		}
	}

	// ID token (OpenID Connect Core 3.1.3.7): aud contains the client id, azp is the client id when several audiences.
	function checkIdTokenAudience(claims, clientId) {
		var list = audiences(claims);
		if (!contains(list, clientId)) {
			fail("JWT audience does not contain the configured client id");
		}
		if (list.length > 1 && claims.azp !== clientId) {
			fail("JWT azp is not the configured client id");
		}
	}

	function checkSubject(claims) {
		if (!nonEmpty(claims.sub)) {
			fail("JWT sub is missing");
		}
	}

	// Implicit / hybrid flow: at_hash binds the id_token to the access token returned with it.
	function checkAccessTokenHash(parsed, accessToken) {
		if (!isString(accessToken) || String(accessToken).length == 0 || !nonEmpty(parsed.claims.at_hash) ||
				platform().accessTokenHash(String(parsed.header.alg), String(accessToken)) !== parsed.claims.at_hash) {
			fail("JWT at_hash does not match the access token");
		}
	}

	function verified(parsed, mode) {
		return { ok: true, claims: parsed.claims, header: parsed.header, mode: mode };
	}

	function guard(run) {
		try {
			return run();
		} catch (e) {
			if (e instanceof VerificationError) {
				return { ok: false, error: e.message };
			}
			return { ok: false, error: "verification failure: " + (e && e.message ? e.message : e) };
		}
	}

	/**
	 * id_token verified with the discovery document of its issuer; a {tenantid} issuer template (Microsoft
	 * common / organizations authorities) is resolved with the token tid only.
	 */
	function verifyIdToken(parsed, discoveryUrl, clientId, algorithms, accessToken) {
		var config = discovery(discoveryUrl);
		var issuer = String(config.issuer);
		checkSignature(parsed, config.jwks_uri, algorithms);
		if (issuer.indexOf("{tenantid}") != -1) {
			if (!isString(parsed.claims.tid) || !GUID.test(String(parsed.claims.tid))) {
				fail("JWT tid is invalid");
			}
			issuer = issuer.replace("{tenantid}", String(parsed.claims.tid));
		}
		if (parsed.claims.iss !== issuer) {
			fail("JWT issuer does not match the configured issuer");
		}
		checkIdTokenAudience(parsed.claims, clientId);
		checkTime(parsed.claims, true);
		checkSubject(parsed.claims);
		checkAccessTokenHash(parsed, accessToken);
		return parsed;
	}

	function isMicrosoftIssuer(issuer) {
		return isString(issuer) && /^https:\/\/(login\.microsoftonline\.com|sts\.windows\.net)\//i.test(String(issuer));
	}

	function wellKnown(issuer) {
		return issuer.replace(/\/+$/, "") + "/.well-known/openid-configuration";
	}

	// Discovery document of the Microsoft tenant of a v2 / v1 id_token issuer (the signature then proves it).
	function microsoftDiscovery(tokenIssuer) {
		var match = /^https:\/\/(?:login\.microsoftonline\.com\/([0-9a-f-]{36})\/v2\.0|sts\.windows\.net\/([0-9a-f-]{36})\/)$/.exec(isString(tokenIssuer) ? String(tokenIssuer) : "");
		if (match == null || !GUID.test(match[1] || match[2])) {
			fail("id_token issuer is not a Microsoft tenant issuer");
		}
		return MICROSOFT_AUTHORITY + (match[1] ? match[1] + "/v2.0" : match[2]) + "/.well-known/openid-configuration";
	}

	function acceptedAudiences(clientId) {
		var accepted = [clientId];
		var extra = optionalSymbol("lib_oauth.openid.audience").split(",");
		for (var i = 0; i < extra.length; i++) {
			if (extra[i].trim().length > 0) {
				accepted.push(extra[i].trim());
			}
		}
		return accepted;
	}

	function intersects(list, accepted) {
		for (var i = 0; i < list.length; i++) {
			if (contains(accepted, list[i])) {
				return true;
			}
		}
		return false;
	}

	function numericDate(value, what) {
		var number = typeof value === "number" ? value : Number(String(value));
		if (!isFinite(number)) {
			fail(what + " is invalid");
		}
		return number;
	}

	/**
	 * RFC 7662 response of the trusted introspection endpoint, authoritative for every access token:
	 * active, sub, exp / nbf when present, iss when both it and the configured issuer are known.
	 * Returns whether it shows the token was issued for the configured client (client_id or aud).
	 */
	function checkIntrospection(introspection, clientId, accepted, configuredIssuer) {
		if (introspection == null || typeof introspection !== "object" || isArray(introspection)) {
			fail("introspection response is missing");
		}
		if (!(introspection.active === true || String(introspection.active) === "true")) {
			fail("introspection: token is not active");
		}
		if (!nonEmpty(introspection.sub)) {
			fail("introspection: sub is missing");
		}
		var now = Math.floor(platform().now() / 1000);
		if (introspection.exp != null && introspection.exp !== "" && now >= numericDate(introspection.exp, "introspection exp") + CLOCK_SKEW_SECONDS) {
			fail("introspection: token is expired");
		}
		if (introspection.nbf != null && introspection.nbf !== "" && numericDate(introspection.nbf, "introspection nbf") > now + CLOCK_SKEW_SECONDS) {
			fail("introspection: token is not valid yet");
		}
		if (nonEmpty(configuredIssuer) && nonEmpty(introspection.iss) && String(introspection.iss) !== configuredIssuer) {
			fail("introspection issuer does not match the configured issuer");
		}
		return introspection.client_id === clientId || String(introspection.client_id) === clientId ||
			intersects(stringList(introspection.aud, "introspection aud"), accepted);
	}

	// Compact JWS whose header names an algorithm, or null for an opaque (or encrypted) access token.
	function parseIfJws(token) {
		try {
			var parsed = parse(token);
			return nonEmpty(parsed.header.alg) ? parsed : null;
		} catch (e) {
			return null;
		}
	}

	function copy(object) {
		var result = {};
		for (var key in object) {
			if (Object.prototype.hasOwnProperty.call(object, key)) {
				result[key] = object[key];
			}
		}
		return result;
	}

	/* ------------------------------------------------------------ providers */

	/** Google id_token obtained by loginGoogleWithCode (code exchange). */
	api.verifyGoogleIdToken = function (idToken) {
		return guard(function () {
			var clientId = configured("lib_oauth.google.clientid");
			var parsed = parse(idToken);
			checkSignature(parsed, discovery(GOOGLE_DISCOVERY).jwks_uri, ["RS256"]);
			if (!contains(GOOGLE_ISSUERS, parsed.claims.iss)) {
				fail("JWT issuer is not Google");
			}
			checkIdTokenAudience(parsed.claims, clientId);
			checkTime(parsed.claims, true);
			checkSubject(parsed.claims);
			return verified(parsed, "id_token");
		});
	};

	/**
	 * Microsoft identity platform (v2.0) id_token sent by the OAuth action with its access token
	 * (implicit flow "id_token token"): the at_hash claim binds the access token to this id_token.
	 */
	api.verifyAzureAdIdToken = function (idToken, accessToken) {
		return guard(function () {
			var clientId = configured("lib_oauth.azuread.clientid");
			// same default as the OAuth action when no tenant is configured
			var tenant = optionalSymbol("lib_oauth.azuread.tenantid") || "common";
			if (!/^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(tenant)) {
				fail("symbol lib_oauth.azuread.tenantid is invalid");
			}
			var parsed = parse(idToken);
			var discoveryUrl = MICROSOFT_AUTHORITY + tenant + "/v2.0/.well-known/openid-configuration";
			if (String(discovery(discoveryUrl).issuer).indexOf(MICROSOFT_AUTHORITY) != 0) {
				fail("unexpected Microsoft issuer");
			}
			return verified(verifyIdToken(parsed, discoveryUrl, clientId, ["RS256"], accessToken), "id_token");
		});
	};

	/**
	 * loginOpenIDWithAccessToken: access token declared active by the trusted introspection endpoint.
	 *
	 * - The introspection response is always checked (see checkIntrospection).
	 * - Opaque (non JWS) access token: the introspection response is authoritative, it must also show the
	 *   token was issued for lib_oauth.openid.clientid; the returned claims are the introspection response.
	 * - JWT access token: signature (issuer JWKS), iss, audience (aud / azp / client_id / cid / appid, or the
	 *   introspection client_id / aud), dates and sub equal to the introspected sub.
	 * - Microsoft (issuer login.microsoftonline.com / sts.windows.net, or a nonce in the JWT header as in
	 *   Graph access tokens, which only Microsoft can verify): the id_token sent with the access token is
	 *   verified instead (issuer discovery, aud = client id, at_hash of the access token, sub equal to the
	 *   introspected sub); without id_token the opaque token rules apply. The claims of such an access
	 *   token are never used.
	 */
	api.verifyOpenIdLogin = function (accessToken, introspection, idToken) {
		return guard(function () {
			var clientId = configured("lib_oauth.openid.clientid");
			var accepted = acceptedAudiences(clientId);
			var configuredIssuer = optionalSymbol("lib_oauth.openid.issuer");
			if (configuredIssuer && !isAllowedUrl(configuredIssuer)) {
				fail("OpenID issuer must be an https URL");
			}
			var introspectionAudience = checkIntrospection(introspection, clientId, accepted, configuredIssuer);
			var subject = String(introspection.sub);
			var introspectedIssuer = nonEmpty(introspection.iss) ? String(introspection.iss) : "";
			var issuer = configuredIssuer || introspectedIssuer;

			function introspectionOnly(mode) {
				if (!introspectionAudience) {
					fail("introspection response does not show the token was issued for the configured client id");
				}
				return { ok: true, claims: copy(introspection), mode: mode };
			}

			if (!isString(accessToken) || String(accessToken).length == 0) {
				fail("access token is missing");
			}
			var parsed = parseIfJws(accessToken);
			if (parsed == null) {
				return introspectionOnly("introspection");
			}

			if (parsed.header.nonce != null || isMicrosoftIssuer(issuer) || isMicrosoftIssuer(parsed.claims.iss)) {
				if (!nonEmpty(idToken)) {
					return introspectionOnly("introspection");
				}
				var id = parse(idToken);
				// configured issuer (e.g. https://login.microsoftonline.com/<tenant>/v2.0), a non Microsoft introspected
				// issuer, or else the Microsoft tenant named by the id_token
				var base = configuredIssuer || (isMicrosoftIssuer(introspectedIssuer) || isMicrosoftIssuer(parsed.claims.iss) ? "" : introspectedIssuer);
				verifyIdToken(id, base ? wellKnown(base) : microsoftDiscovery(id.claims.iss), clientId, ASYMMETRIC, String(accessToken));
				if (id.claims.sub !== subject) {
					fail("id_token sub does not match the introspection response");
				}
				return verified(id, "id_token");
			}

			if (!nonEmpty(issuer)) {
				fail("symbol lib_oauth.openid.issuer is not configured and the introspection response has no iss");
			}
			if (!isAllowedUrl(issuer)) {
				fail("OpenID issuer must be an https URL");
			}
			var config = discovery(wellKnown(issuer));
			if (config.issuer !== issuer) {
				fail("discovery issuer does not match the configured issuer");
			}
			checkSignature(parsed, config.jwks_uri, ASYMMETRIC);
			var claims = parsed.claims;
			if (claims.iss !== issuer) {
				fail("JWT issuer does not match the configured issuer");
			}
			// Access tokens target a resource: accept the client id as audience or as the authorized party
			// (azp, RFC 9068 client_id, Okta cid, Azure appid) or as reported by the introspection endpoint.
			if (!(introspectionAudience || intersects(audiences(claims), accepted) || claims.azp === clientId ||
					claims.client_id === clientId || claims.cid === clientId || claims.appid === clientId)) {
				fail("JWT was not issued for the configured client id");
			}
			checkTime(claims, false);
			checkSubject(claims);
			if (claims.sub !== subject) {
				fail("JWT sub does not match the introspection response");
			}
			return verified(parsed, "jwt");
		});
	};

	/* --------------------------------------------------------- OpenID groups */

	var GROUPS_MAX = 200;
	var GROUP_MAX_LENGTH = 256;
	// a claim name: printable ASCII without space (groups, roles, realm_access.roles, https://example.com/groups)
	var CLAIM_NAME = /^[\x21-\x7E]{1,256}$/;
	var CONTROL = /[\u0000-\u001F\u007F]/;

	function hasOwn(object, key) {
		return Object.prototype.hasOwnProperty.call(object, key);
	}

	// The claim of that exact name, else the dotted path in nested objects (realm_access.roles); undefined when absent.
	function claimValue(claims, name) {
		if (claims == null || typeof claims !== "object" || isArray(claims)) {
			return undefined;
		}
		if (hasOwn(claims, name)) {
			return claims[name];
		}
		if (name.indexOf(".") == -1) {
			return undefined;
		}
		var parts = name.split(".");
		var value = claims;
		for (var i = 0; i < parts.length; i++) {
			if (value == null || typeof value !== "object" || isArray(value) || parts[i].length == 0 || !hasOwn(value, parts[i])) {
				return undefined;
			}
			value = value[parts[i]];
		}
		return value;
	}

	/**
	 * Groups carried by the claim `name` of claims that are already verified:
	 * - { found: false } when the claim is absent (or null);
	 * - { found: true, groups: [...], dropped: n } for a string (one group) or a list of strings: values trimmed,
	 *   duplicates removed, empty values dropped, values with control characters or longer than 256 characters dropped
	 *   and counted;
	 * - { found: true, error: "..." } for any other value or more than 200 groups.
	 */
	api.groupsFromClaims = function (claims, name) {
		var value = claimValue(claims, String(name));
		if (value === undefined || value === null) {
			return { found: false };
		}
		var list;
		try {
			list = stringList(value, "claim " + name);
		} catch (e) {
			return { found: true, error: "claim " + name + " is not a string or a list of strings" };
		}
		var groups = [];
		var dropped = 0;
		for (var i = 0; i < list.length; i++) {
			var group = list[i].replace(/^\s+|\s+$/g, "");
			if (group.length == 0) {
				continue;
			}
			if (group.length > GROUP_MAX_LENGTH || CONTROL.test(group)) {
				dropped++;
				continue;
			}
			if (!contains(groups, group)) {
				groups.push(group);
			}
		}
		if (groups.length > GROUPS_MAX) {
			return { found: true, error: "claim " + name + " holds more than " + GROUPS_MAX + " groups" };
		}
		return { found: true, groups: groups, dropped: dropped };
	};

	// Issuer of the OpenID provider: lib_oauth.openid.issuer, else the iss of the introspection response.
	function openIdIssuer(introspection) {
		var issuer = optionalSymbol("lib_oauth.openid.issuer") || (nonEmpty(introspection.iss) ? String(introspection.iss) : "");
		if (!nonEmpty(issuer)) {
			fail("symbol lib_oauth.openid.issuer is not configured and the introspection response has no iss");
		}
		if (!isAllowedUrl(issuer)) {
			fail("OpenID issuer must be an https URL");
		}
		return issuer;
	}

	// Discovery document of the provider of a verified login: the one of the configured issuer, else, after the Microsoft
	// rules, the one of the issuer of the verified id_token (its Microsoft tenant), else the one of the introspection iss.
	function openIdDiscovery(verification, introspection) {
		if (verification.mode === "id_token" && !optionalSymbol("lib_oauth.openid.issuer")) {
			var tokenIssuer = verification.claims.iss;
			return discovery(isMicrosoftIssuer(tokenIssuer) ? microsoftDiscovery(tokenIssuer) : wellKnown(String(tokenIssuer)));
		}
		var issuer = openIdIssuer(introspection);
		var config = discovery(wellKnown(issuer));
		if (config.issuer !== issuer && String(config.issuer).indexOf("{tenantid}") == -1) {
			fail("discovery issuer does not match the configured issuer");
		}
		return config;
	}

	/**
	 * id_token sent with an access token that verifyOpenIdLogin accepted from its JWT or introspection rules (the
	 * Microsoft rules already verify it): signature with the issuer JWKS, iss, aud / azp = client id, exp / iat, at_hash
	 * of the access token and sub of the introspection response, exactly as for Microsoft.
	 */
	function verifyOpenIdIdToken(idToken, accessToken, introspection) {
		var clientId = configured("lib_oauth.openid.clientid");
		var issuer = openIdIssuer(introspection);
		var discoveryUrl = wellKnown(issuer);
		var config = discovery(discoveryUrl);
		if (config.issuer !== issuer && String(config.issuer).indexOf("{tenantid}") == -1) {
			fail("discovery issuer does not match the configured issuer");
		}
		var parsed = parse(idToken);
		verifyIdToken(parsed, discoveryUrl, clientId, ASYMMETRIC, String(accessToken));
		if (parsed.claims.sub !== String(introspection.sub)) {
			fail("id_token sub does not match the introspection response");
		}
		return parsed.claims;
	}

	// Claims of the userinfo endpoint of the provider (https, from its discovery document), for the verified subject only.
	function userInfo(verification, introspection, accessToken) {
		var endpoint = openIdDiscovery(verification, introspection).userinfo_endpoint;
		if (!nonEmpty(endpoint)) {
			fail("the discovery document has no userinfo_endpoint");
		}
		if (!isAllowedUrl(endpoint)) {
			fail("refusing to call " + endpoint);
		}
		var text;
		try {
			text = String(platform().fetchWithBearer(String(endpoint), String(accessToken)));
		} catch (e) {
			fail("cannot call " + endpoint + ": " + (e && e.message ? e.message : e));
		}
		var claims = parseJson(text, "userinfo response");
		if (claims.sub !== String(introspection.sub)) {
			fail("userinfo sub does not match the verified user");
		}
		return claims;
	}

	// The provider left the groups out of its token (Microsoft group overage: hasgroups or _claim_names).
	function groupsLeftOut(claims, name) {
		if (claims == null || typeof claims !== "object") {
			return false;
		}
		var names = claims._claim_names;
		return claims.hasgroups === true || String(claims.hasgroups) === "true" ||
			(names != null && typeof names === "object" && !isArray(names) && hasOwn(names, name));
	}

	/**
	 * Groups of an OpenID user, after verifyOpenIdLogin accepted the login (verification = its result), for the claim
	 * named by lib_oauth.openid.groups_claim. Read from verified sources only, in this order, the first one that holds
	 * the claim decides:
	 *   1. the id_token: the one verified by the Microsoft rules, or the id_token sent with the access token, verified
	 *      here (signature, iss, aud = client id, dates, at_hash of the access token, sub of the introspection);
	 *   2. the claims verifyOpenIdLogin returned (JWT access token or introspection response);
	 *   3. the userinfo endpoint of the provider (from its discovery document, https), whose sub must be the user.
	 * Never the claims of a token that is not verified, never a value sent by the client.
	 * Returns { enabled: false } when the symbol is empty, else { enabled: true, claim, state, groups, source, warnings }:
	 * state "present" with the groups (possibly none), or "missing" (no group) when no source holds the claim or its value
	 * is invalid. Never throws.
	 */
	api.openIdGroups = function (verification, accessToken, introspection, idToken) {
		var name = optionalSymbol("lib_oauth.openid.groups_claim");
		if (!name) {
			return { enabled: false };
		}
		var result = { enabled: true, claim: name, state: "missing", groups: [], source: "", warnings: [] };
		if (!CLAIM_NAME.test(name)) {
			result.claim = "";
			result.warnings.push("symbol lib_oauth.openid.groups_claim is not a claim name");
			return result;
		}
		if (verification == null || verification.ok !== true || introspection == null || typeof introspection !== "object" ||
				!nonEmpty(introspection.sub) || !isString(accessToken) || String(accessToken).length == 0) {
			result.warnings.push("the login is not verified");
			return result;
		}
		var inspected = [];
		function decide(source, claims) {
			inspected.push(claims);
			var read = api.groupsFromClaims(claims, name);
			if (!read.found) {
				return false;
			}
			result.source = source;
			if (read.error) {
				result.warnings.push(read.error + " (" + source + "), the user gets no group");
				return true;
			}
			result.state = "present";
			result.groups = read.groups;
			if (read.dropped > 0) {
				result.warnings.push(read.dropped + " invalid group name(s) ignored (" + source + ")");
			}
			return true;
		}
		var idClaims = null;
		if (verification.mode === "id_token") {
			idClaims = verification.claims;
		} else if (nonEmpty(idToken)) {
			var checked = guard(function () {
				return { ok: true, claims: verifyOpenIdIdToken(String(idToken), String(accessToken), introspection) };
			});
			if (checked.ok) {
				idClaims = checked.claims;
			} else {
				result.warnings.push("id_token not used: " + checked.error);
			}
		}
		if (idClaims != null && decide("id_token", idClaims)) {
			return result;
		}
		if (verification.mode !== "id_token" && decide(verification.mode === "jwt" ? "access_token" : "introspection", verification.claims)) {
			return result;
		}
		var info = guard(function () {
			return { ok: true, claims: userInfo(verification, introspection, String(accessToken)) };
		});
		if (!info.ok) {
			result.warnings.push("userinfo not read: " + info.error);
		} else if (decide("userinfo", info.claims)) {
			return result;
		}
		for (var i = 0; i < inspected.length; i++) {
			if (groupsLeftOut(inspected[i], name)) {
				result.warnings.push("the provider left the groups out of its token (too many groups)");
				break;
			}
		}
		result.warnings.push("claim " + name + " not found, the user gets no group");
		return result;
	};

	/**
	 * Graph /me id and id_token oid designate the same user (personal accounts: 16 hex digits vs padded GUID).
	 * oid is only emitted with the profile scope: an absent oid is not a mismatch (at_hash already binds the tokens).
	 */
	api.graphUserMatchesIdToken = function (graphId, oid) {
		function normalize(value) {
			return value == null ? "" : String(value).toLowerCase().replace(/-/g, "").replace(/^0+/, "");
		}
		var a = normalize(graphId);
		if (a.length == 0) {
			return false;
		}
		return oid == null || String(oid).length == 0 || a === normalize(oid);
	};

	api.isAllowedUrl = isAllowedUrl;
	api.javaPlatform = javaPlatform;

	return api;
})();
