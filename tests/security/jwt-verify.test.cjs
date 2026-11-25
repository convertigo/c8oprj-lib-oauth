const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const project = path.resolve(__dirname, '../..');
const helper = fs.readFileSync(path.join(project, 'js/jwt_verify.js'), 'utf8');

const GOOGLE_DISCOVERY = 'https://accounts.google.com/.well-known/openid-configuration';
const GOOGLE_JWKS = 'https://www.googleapis.com/oauth2/v3/certs';
const TENANT = '11111111-2222-3333-4444-555555555555';
const OTHER_TENANT = '99999999-8888-7777-6666-555555555555';
const MS = 'https://login.microsoftonline.com/';
const KC = 'https://idp.example.com/realms/c8o';

const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const plain = (value) => JSON.parse(JSON.stringify(value));

function rsaKey(kid, modulusLength = 2048) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength });
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' } };
}

function ecKey(kid) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig' } };
}

function sign(key, claims, header = {}) {
  const alg = header.alg || (key.jwk.kty === 'EC' ? 'ES256' : 'RS256');
  const input = b64({ typ: 'JWT', alg, kid: key.kid, ...header }) + '.' + b64(claims);
  const hash = 'sha' + alg.slice(2);
  const signature = alg.startsWith('ES')
    ? crypto.sign(hash, Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' })
    : crypto.sign(hash, Buffer.from(input), key.privateKey);
  return input + '.' + signature.toString('base64url');
}

function atHash(accessToken) {
  const digest = crypto.createHash('sha256').update(accessToken, 'ascii').digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

// Node implementation of the platform port (the Rhino one is exercised by jwt-verify-rhino.test.cjs).
function load({ symbols = {}, documents = {}, now = Date.now() } = {}) {
  const cache = new Map();
  const fetched = [];
  const clock = { now };
  const platform = {
    now: () => clock.now,
    decodeBase64Url(text) {
      if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not base64url');
      return Buffer.from(text, 'base64url');
    },
    utf8: (data) => new TextDecoder('utf-8', { fatal: true }).decode(data),
    verifySignature(alg, jwk, input, signature) {
      const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      const hash = 'sha' + alg.slice(2);
      return alg.startsWith('ES')
        ? crypto.verify(hash, Buffer.from(input, 'ascii'), { key, dsaEncoding: 'ieee-p1363' }, signature)
        : crypto.verify(hash, Buffer.from(input, 'ascii'), key, signature);
    },
    accessTokenHash: (alg, accessToken) => atHash(accessToken),
    fetch(url) {
      fetched.push(url);
      if (!(url in documents)) throw new Error('404');
      return JSON.stringify(documents[url]);
    },
    cacheGet: (key) => (cache.has(key) ? cache.get(key) : null),
    cachePut: (key, value) => cache.set(key, value),
    symbol: (name) => symbols[name] || '',
  };
  const sandbox = {};
  vm.runInNewContext(helper, sandbox, { filename: 'jwt_verify.js' });
  sandbox.libOAuthJwt.platform = platform;
  return { jwt: sandbox.libOAuthJwt, fetched, documents, clock };
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

/* ------------------------------------------------------------------ Google */

const googleKey = rsaKey('google-1');
const googleClaims = (extra = {}) => ({
  iss: 'https://accounts.google.com',
  aud: 'google-client',
  azp: 'google-client',
  sub: '1234567890',
  email: 'alice@example.com',
  iat: nowSeconds() - 10,
  exp: nowSeconds() + 3600,
  ...extra,
});

function google(keys = [googleKey], symbols = { 'lib_oauth.google.clientid': 'google-client' }) {
  return load({
    symbols,
    documents: {
      [GOOGLE_DISCOVERY]: { issuer: 'https://accounts.google.com', jwks_uri: GOOGLE_JWKS },
      [GOOGLE_JWKS]: { keys: keys.map((key) => key.jwk) },
    },
  });
}

test('google: a signed id_token for the configured client is accepted', () => {
  const { jwt } = google();
  const result = jwt.verifyGoogleIdToken(sign(googleKey, googleClaims()));
  assert.equal(result.ok, true, result.error);
  assert.equal(result.claims.sub, '1234567890');
  assert.equal(result.claims.email, 'alice@example.com');
  assert.equal(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims({ iss: 'accounts.google.com' }))).ok, true);
});

test('google: unsigned, symmetric and tampered tokens are refused', () => {
  const { jwt } = google();
  const token = sign(googleKey, googleClaims());
  const [header, , signature] = token.split('.');
  const forged = header + '.' + b64(googleClaims({ email: 'admin@example.com' })) + '.' + signature;
  assert.match(jwt.verifyGoogleIdToken(forged).error, /signature is invalid/);
  assert.match(jwt.verifyGoogleIdToken(b64({ alg: 'none' }) + '.' + b64(googleClaims()) + '.').error, /not a signed compact JWT/);
  assert.match(jwt.verifyGoogleIdToken(b64({ alg: 'none' }) + '.' + b64(googleClaims()) + '.AA').error, /algorithm none/);
  // HS256 with the public key as secret (algorithm confusion)
  const input = b64({ alg: 'HS256', kid: 'google-1' }) + '.' + b64(googleClaims());
  const hmac = crypto.createHmac('sha256', JSON.stringify(googleKey.jwk)).update(input).digest('base64url');
  assert.match(jwt.verifyGoogleIdToken(input + '.' + hmac).error, /algorithm HS256/);
  assert.match(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims(), { crit: ['exp'] })).error, /critical/);
  assert.equal(jwt.verifyGoogleIdToken(null).ok, false);
  assert.equal(jwt.verifyGoogleIdToken('a.b').ok, false);
  assert.equal(jwt.verifyGoogleIdToken(b64('not json') + '.' + b64(googleClaims()) + '.AA').ok, false);
});

test('google: a token signed by another key with the same kid is refused', () => {
  const { jwt } = google();
  const attacker = rsaKey('google-1');
  assert.match(jwt.verifyGoogleIdToken(sign(attacker, googleClaims())).error, /signature is invalid/);
});

test('google: issuer, audience and dates are enforced', () => {
  const { jwt } = google();
  const now = nowSeconds();
  const reject = (claims, pattern) => assert.match(jwt.verifyGoogleIdToken(sign(googleKey, claims)).error, pattern);
  reject(googleClaims({ iss: 'https://evil.example.com' }), /issuer/);
  reject(googleClaims({ aud: 'other-client', azp: 'other-client' }), /audience/);
  reject(googleClaims({ aud: ['google-client', 'other-client'], azp: 'other-client' }), /azp/);
  reject(googleClaims({ aud: ['google-client', 'other-client'], azp: undefined }), /azp/);
  reject(googleClaims({ exp: now - 301 }), /expired/);
  reject(googleClaims({ exp: undefined }), /exp is missing/);
  reject(googleClaims({ exp: String(now + 3600) }), /exp is missing/);
  reject(googleClaims({ nbf: now + 301 }), /not valid yet/);
  reject(googleClaims({ iat: now + 301 }), /iat/);
  reject(googleClaims({ iat: undefined }), /iat/);
  reject(googleClaims({ sub: '' }), /sub/);
  // 5 minutes of clock skew
  assert.equal(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims({ exp: now - 200, nbf: now + 200, iat: now + 200 }))).ok, true);
  assert.equal(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims({ aud: ['google-client', 'other'], azp: 'google-client' }))).ok, true);
});

test('google: the client id must be configured', () => {
  for (const symbols of [{}, { 'lib_oauth.google.clientid': '${lib_oauth.google.clientid}' }]) {
    const { jwt } = google([googleKey], symbols);
    assert.match(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims())).error, /lib_oauth\.google\.clientid is not configured/);
  }
});

test('jwks: keys are cached, an unknown kid refreshes them at most once a minute', () => {
  const { jwt, fetched, documents, clock } = google();
  assert.equal(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims())).ok, true);
  assert.equal(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims())).ok, true);
  assert.deepEqual(fetched, [GOOGLE_DISCOVERY, GOOGLE_JWKS]);

  const rotated = rsaKey('google-2');
  documents[GOOGLE_JWKS] = { keys: [googleKey.jwk, rotated.jwk] };
  // fetched less than a minute ago: an unknown kid does not hammer the provider
  assert.match(jwt.verifyGoogleIdToken(sign(rotated, googleClaims())).error, /no signing key/);
  assert.equal(fetched.length, 2);
  clock.now += 61 * 1000;
  assert.equal(jwt.verifyGoogleIdToken(sign(rotated, googleClaims())).ok, true);
  assert.deepEqual(fetched, [GOOGLE_DISCOVERY, GOOGLE_JWKS, GOOGLE_JWKS]);
  clock.now += 61 * 1000;
  assert.match(jwt.verifyGoogleIdToken(sign(rsaKey('unknown'), googleClaims())).error, /no signing key/);
  assert.equal(fetched.length, 4);
  // provider unreachable: refused, never accepted unverified
  const offline = google();
  delete offline.documents[GOOGLE_JWKS];
  assert.match(offline.jwt.verifyGoogleIdToken(sign(googleKey, googleClaims())).error, /cannot fetch/);
});

test('jwks: keys whose type, use or alg do not match are ignored', () => {
  let { jwt } = google([{ ...googleKey, jwk: { ...googleKey.jwk, use: 'enc' } }]);
  assert.match(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims())).error, /no signing key/);
  ({ jwt } = google([{ ...googleKey, jwk: { ...googleKey.jwk, alg: 'RS512' } }]));
  assert.match(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims())).error, /no signing key/);
  // no kid in the header: every compatible key is tried
  ({ jwt } = google([rsaKey('a'), googleKey]));
  assert.equal(jwt.verifyGoogleIdToken(sign(googleKey, googleClaims(), { kid: undefined })).ok, true);
});

/* ----------------------------------------------------------------- Azure AD */

const azureKey = rsaKey('ms-1');
const ACCESS_TOKEN = 'EwB-graph-access-token';

function azure(tenant = TENANT, issuerTenant = tenant) {
  const discovery = MS + tenant + '/v2.0/.well-known/openid-configuration';
  const jwks = MS + tenant + '/discovery/v2.0/keys';
  return load({
    symbols: { 'lib_oauth.azuread.clientid': 'azure-client', 'lib_oauth.azuread.tenantid': tenant },
    documents: {
      [discovery]: { issuer: MS + issuerTenant + '/v2.0', jwks_uri: jwks },
      [jwks]: { keys: [azureKey.jwk] },
    },
  });
}

const azureClaims = (tid = TENANT, extra = {}) => ({
  iss: MS + tid + '/v2.0',
  aud: 'azure-client',
  tid,
  sub: 'pairwise-sub',
  oid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  at_hash: atHash(ACCESS_TOKEN),
  iat: nowSeconds(),
  nbf: nowSeconds(),
  exp: nowSeconds() + 3600,
  ...extra,
});

test('azure: id_token of the configured tenant bound to the access token is accepted', () => {
  const { jwt } = azure();
  const result = jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims()), ACCESS_TOKEN);
  assert.equal(result.ok, true, result.error);
  assert.equal(result.claims.oid, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
});

test('azure: at_hash must bind the id_token to the access token', () => {
  const { jwt } = azure();
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims()), 'another-access-token').error, /at_hash/);
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims(TENANT, { at_hash: undefined })), ACCESS_TOKEN).error, /at_hash/);
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims()), '').error, /at_hash/);
  assert.match(jwt.verifyAzureAdIdToken('', ACCESS_TOKEN).error, /token is not a signed compact JWT/);
});

test('azure: a single-tenant configuration refuses other tenants and other clients', () => {
  const { jwt } = azure();
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims(OTHER_TENANT)), ACCESS_TOKEN).error, /issuer/);
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims(TENANT, { aud: 'graph' })), ACCESS_TOKEN).error, /audience/);
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims(TENANT, { exp: nowSeconds() - 400 })), ACCESS_TOKEN).error, /expired/);
});

test('azure: multi-tenant issuer template is resolved with the token tid only', () => {
  const { jwt } = azure('common', '{tenantid}');
  assert.equal(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims(OTHER_TENANT)), ACCESS_TOKEN).ok, true);
  // issuer of one tenant, tid of another
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims(OTHER_TENANT, { tid: TENANT })), ACCESS_TOKEN).error, /issuer/);
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims('{tenantid}')), ACCESS_TOKEN).error, /tid/);
  assert.match(jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims(TENANT, { tid: undefined })), ACCESS_TOKEN).error, /tid/);
});

test('azure: tenant symbol is validated and defaults to common', () => {
  const evil = load({ symbols: { 'lib_oauth.azuread.clientid': 'azure-client', 'lib_oauth.azuread.tenantid': 'evil.example.com/x' } });
  assert.match(evil.jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims()), ACCESS_TOKEN).error, /tenantid is invalid/);
  const unset = load({ symbols: { 'lib_oauth.azuread.clientid': 'azure-client' } });
  unset.jwt.verifyAzureAdIdToken(sign(azureKey, azureClaims()), ACCESS_TOKEN);
  assert.deepEqual(unset.fetched, [MS + 'common/v2.0/.well-known/openid-configuration']);
});

test('azure: the Graph user must be the id_token user when oid is present', () => {
  const { jwt } = azure();
  assert.equal(jwt.graphUserMatchesIdToken('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee'), true);
  // personal account: Graph returns the CID, the id_token the padded GUID
  assert.equal(jwt.graphUserMatchesIdToken('66f33332eca7ea81', '00000000-0000-0000-66f3-3332eca7ea81'), true);
  assert.equal(jwt.graphUserMatchesIdToken('ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'), false);
  // oid needs the profile scope: without it at_hash is the binding
  assert.equal(jwt.graphUserMatchesIdToken('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', null), true);
  assert.equal(jwt.graphUserMatchesIdToken(null, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'), false);
});

/* ------------------------------------------------------------------ OpenID */

const kcKey = ecKey('kc-1');
const kcClaims = (extra = {}) => ({
  iss: KC,
  aud: 'account',
  azp: 'c8o-client',
  sub: 'user-1',
  name: 'Alice',
  iat: nowSeconds(),
  exp: nowSeconds() + 300,
  ...extra,
});

function openid(symbols = {}, issuer = KC) {
  return load({
    symbols: { 'lib_oauth.openid.clientid': 'c8o-client', ...symbols },
    documents: {
      [issuer + '/.well-known/openid-configuration']: { issuer, jwks_uri: issuer + '/protocol/openid-connect/certs' },
      [issuer + '/protocol/openid-connect/certs']: { keys: [kcKey.jwk] },
    },
  });
}

const introspection = (extra = {}) => ({ active: true, sub: 'user-1', iss: KC, client_id: 'c8o-client', ...extra });
const login = (jwt, accessToken, introspected, idToken) => {
  const result = jwt.verifyOpenIdLogin(accessToken, introspected, idToken);
  return result.ok ? { ...result, claims: plain(result.claims) } : result;
};

test('openid: a JWT access token is verified against the issuer JWKS', () => {
  const { jwt, fetched } = openid();
  const result = login(jwt, sign(kcKey, kcClaims()), introspection());
  assert.equal(result.ok, true, result.error);
  assert.equal(result.mode, 'jwt');
  assert.equal(result.claims.name, 'Alice');
  assert.deepEqual(fetched, [KC + '/.well-known/openid-configuration', KC + '/protocol/openid-connect/certs']);
  // the configured issuer wins and must agree with the introspection response
  assert.equal(login(openid({ 'lib_oauth.openid.issuer': KC }).jwt, sign(kcKey, kcClaims()), introspection({ iss: '' })).ok, true);
  assert.match(login(openid({ 'lib_oauth.openid.issuer': KC }).jwt, sign(kcKey, kcClaims()), introspection({ iss: 'https://other' })).error, /introspection issuer/);
  assert.match(login(jwt, sign(kcKey, kcClaims()), introspection({ iss: '' })).error, /issuer is not configured/);
});

test('openid: a JWT access token also passes the introspection checks', () => {
  const { jwt } = openid();
  const token = sign(kcKey, kcClaims());
  assert.match(login(jwt, token, introspection({ active: false })).error, /not active/);
  assert.match(login(jwt, token, introspection({ exp: nowSeconds() - 400 })).error, /introspection: token is expired/);
  assert.match(login(jwt, token, null).error, /introspection response is missing/);
  // a forged JWT is not downgraded to introspection-only
  const [header, , signature] = token.split('.');
  assert.match(login(jwt, header + '.' + b64(kcClaims({ name: 'Mallory' })) + '.' + signature, introspection()).error, /signature is invalid/);
});

test('openid: the JWT must have been issued for the configured client', () => {
  const { jwt } = openid();
  const token = (extra) => sign(kcKey, kcClaims({ azp: undefined, ...extra }));
  const foreign = introspection({ client_id: 'other' });
  assert.match(login(jwt, token({}), foreign).error, /configured client id/);
  assert.match(login(jwt, token({ azp: 'other' }), foreign).error, /configured client id/);
  assert.equal(login(jwt, token({ aud: ['account', 'c8o-client'] }), foreign).ok, true);
  assert.equal(login(jwt, token({ client_id: 'c8o-client' }), foreign).ok, true);
  assert.equal(login(jwt, token({ cid: 'c8o-client' }), foreign).ok, true);
  assert.equal(login(jwt, token({}), introspection()).ok, true);
  const api = openid({ 'lib_oauth.openid.audience': 'api://default, other-api' }).jwt;
  assert.equal(login(api, token({ aud: 'api://default' }), foreign).ok, true);
});

test('openid: JWT issuer, subject, algorithm and transport are enforced', () => {
  const { jwt } = openid();
  assert.match(login(jwt, sign(kcKey, kcClaims({ iss: KC + '/' })), introspection()).error, /issuer/);
  assert.match(login(jwt, sign(kcKey, kcClaims({ sub: 'user-2' })), introspection()).error, /introspection/);
  assert.match(login(jwt, sign(kcKey, kcClaims()), introspection({ sub: '' })).error, /sub is missing/);
  assert.match(login(jwt, sign(kcKey, kcClaims({ exp: nowSeconds() - 600 })), introspection()).error, /expired/);
  const input = b64({ alg: 'HS256', kid: 'kc-1' }) + '.' + b64(kcClaims());
  assert.match(login(jwt, input + '.' + crypto.createHmac('sha256', 'secret').update(input).digest('base64url'), introspection()).error, /HS256/);
  const mismatch = openid();
  mismatch.documents[KC + '/.well-known/openid-configuration'].issuer = 'https://evil.example.com';
  assert.match(login(mismatch.jwt, sign(kcKey, kcClaims()), introspection()).error, /discovery issuer/);
  // plain http only for a loopback development provider
  const http = 'http://idp.example.com/realms/c8o';
  assert.match(login(openid({}, http).jwt, sign(kcKey, kcClaims({ iss: http })), introspection({ iss: http })).error, /https/);
  const local = 'http://localhost:8080/realms/c8o';
  assert.equal(login(openid({}, local).jwt, sign(kcKey, kcClaims({ iss: local })), introspection({ iss: local })).ok, true);
});

test('openid: an opaque access token is accepted on a valid introspection response', () => {
  const { jwt, fetched } = openid();
  const exp = nowSeconds() + 300;
  for (const accessToken of ['2YotnFZFEjr1zCsicMWpAA', 'abc.def.ghi', 'a.b.c.d.e']) {
    const result = login(jwt, accessToken, introspection({ exp, name: 'Alice' }));
    assert.equal(result.ok, true, accessToken + ' ' + result.error);
    assert.equal(result.mode, 'introspection');
    assert.equal(result.claims.sub, 'user-1');
    assert.equal(result.claims.name, 'Alice');
  }
  assert.deepEqual(fetched, [], 'no discovery needed for opaque tokens');
  // audience from aud, extra audiences, untyped values of an XML round trip
  assert.equal(login(jwt, 'opaque', introspection({ client_id: undefined, aud: ['account', 'c8o-client'] })).ok, true);
  assert.equal(login(jwt, 'opaque', introspection({ client_id: undefined, aud: { item: ['c8o-client'] } })).ok, true);
  assert.equal(login(openid({ 'lib_oauth.openid.audience': 'api://default' }).jwt, 'opaque', introspection({ client_id: 'x', aud: 'api://default' })).ok, true);
  assert.equal(login(jwt, 'opaque', introspection({ active: 'true', exp: String(exp) })).ok, true);
  assert.equal(login(jwt, 'opaque', introspection({ exp: nowSeconds() - 200 })).ok, true, 'clock skew');
});

test('openid: an opaque access token is refused on an unsafe introspection response', () => {
  const { jwt } = openid();
  const reject = (introspected, pattern) => assert.match(login(jwt, 'opaque', introspected).error, pattern);
  reject(introspection({ active: false }), /not active/);
  reject(introspection({ active: 'false' }), /not active/);
  reject(introspection({ active: undefined }), /not active/);
  reject(introspection({ exp: nowSeconds() - 301 }), /expired/);
  reject(introspection({ exp: 'soon' }), /exp is invalid/);
  reject(introspection({ nbf: nowSeconds() + 301 }), /not valid yet/);
  reject(introspection({ client_id: 'other-client' }), /configured client id/);
  reject(introspection({ client_id: undefined, aud: ['account'] }), /configured client id/);
  reject(introspection({ client_id: undefined }), /configured client id/);
  reject(introspection({ sub: undefined }), /sub is missing/);
  reject(null, /introspection response is missing/);
  reject([introspection()], /introspection response is missing/);
  assert.match(login(openid({ 'lib_oauth.openid.issuer': 'https://other.example.com' }).jwt, 'opaque', introspection()).error, /introspection issuer/);
  assert.match(login(jwt, '', introspection()).error, /access token is missing/);
  assert.match(login(openid({ 'lib_oauth.openid.clientid': '' }).jwt, 'opaque', introspection()).error, /clientid is not configured/);
});

/* ---------------------------------------------- OpenID provider = Microsoft */

const ENTRA = MS + TENANT + '/v2.0';
const graphKey = rsaKey('graph-1');

function entra(symbols = {}) {
  return load({
    symbols: { 'lib_oauth.openid.clientid': 'entra-client', ...symbols },
    documents: {
      [ENTRA + '/.well-known/openid-configuration']: { issuer: ENTRA, jwks_uri: MS + TENANT + '/discovery/v2.0/keys' },
      [MS + 'common/v2.0/.well-known/openid-configuration']: { issuer: MS + '{tenantid}/v2.0', jwks_uri: MS + 'common/discovery/v2.0/keys' },
      [MS + TENANT + '/discovery/v2.0/keys']: { keys: [azureKey.jwk] },
      [MS + 'common/discovery/v2.0/keys']: { keys: [azureKey.jwk] },
    },
  });
}

// Graph access token: the header nonce makes the signature unverifiable outside Microsoft.
const graphToken = (claims = {}) => sign(graphKey, {
  iss: 'https://sts.windows.net/' + TENANT + '/', aud: '00000003-0000-0000-c000-000000000000', appid: 'entra-client',
  tid: TENANT, sub: 'graph-pairwise', name: 'Graph Name', exp: nowSeconds() + 3600, ...claims,
}, { nonce: 'abcdef' });

const entraIdToken = (accessToken, extra = {}) => sign(azureKey, {
  iss: ENTRA, aud: 'entra-client', tid: TENANT, sub: 'id-pairwise', name: 'Entra Name', oid: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  at_hash: atHash(accessToken), iat: nowSeconds(), exp: nowSeconds() + 3600, ...extra,
});

const entraIntrospection = (extra = {}) => ({ active: true, sub: 'id-pairwise', client_id: 'entra-client', ...extra });

test('openid/microsoft: a Graph access token is bound to a verified id_token', () => {
  const access = graphToken();
  const { jwt, fetched } = entra();
  const result = login(jwt, access, entraIntrospection(), entraIdToken(access));
  assert.equal(result.ok, true, result.error);
  assert.equal(result.mode, 'id_token');
  assert.equal(result.claims.name, 'Entra Name', 'claims come from the id_token, never from the Graph token');
  assert.deepEqual(fetched, [ENTRA + '/.well-known/openid-configuration', MS + TENANT + '/discovery/v2.0/keys']);
  // configured multi-tenant authority: issuer template resolved with the id_token tid
  const common = entra({ 'lib_oauth.openid.issuer': MS + 'common/v2.0' });
  assert.equal(login(common.jwt, access, entraIntrospection(), entraIdToken(access)).ok, true);
});

test('openid/microsoft: the id_token must be valid, for this client and for this access token', () => {
  const access = graphToken();
  const { jwt } = entra();
  assert.match(login(jwt, access, entraIntrospection(), entraIdToken('another-access-token')).error, /at_hash/);
  assert.match(login(jwt, access, entraIntrospection(), entraIdToken(access, { aud: 'other-client' })).error, /audience/);
  assert.match(login(jwt, access, entraIntrospection(), entraIdToken(access, { exp: nowSeconds() - 400 })).error, /expired/);
  assert.match(login(jwt, access, entraIntrospection({ sub: 'someone-else' }), entraIdToken(access)).error, /sub does not match/);
  assert.match(login(jwt, access, entraIntrospection(), sign(rsaKey('ms-1'), { iss: ENTRA, aud: 'entra-client', sub: 'id-pairwise', tid: TENANT, at_hash: atHash(access), iat: nowSeconds(), exp: nowSeconds() + 60 })).error, /signature is invalid/);
  assert.match(login(jwt, access, entraIntrospection(), entraIdToken(access, { iss: 'https://evil.example.com/' + TENANT + '/v2.0' })).error, /not a Microsoft tenant issuer/);
  assert.match(login(jwt, access, entraIntrospection({ active: false }), entraIdToken(access)).error, /not active/);
});

test('openid/microsoft: without id_token the introspection-only rules apply', () => {
  const access = graphToken({ name: 'Forged Name' });
  const { jwt, fetched } = entra();
  const result = login(jwt, access, entraIntrospection({ name: 'Introspected Name' }));
  assert.equal(result.ok, true, result.error);
  assert.equal(result.mode, 'introspection');
  assert.equal(result.claims.name, 'Introspected Name');
  assert.deepEqual(fetched, []);
  assert.match(login(jwt, access, entraIntrospection({ client_id: 'other' })).error, /configured client id/);
  assert.match(login(jwt, access, entraIntrospection({ exp: nowSeconds() - 400 })).error, /expired/);
  // Microsoft issuer without nonce header (v1 or v2 access token for another API) takes the same path
  const plainMs = sign(graphKey, { iss: ENTRA, aud: 'api://x', sub: 's', exp: nowSeconds() + 60 });
  assert.equal(login(jwt, plainMs, entraIntrospection()).mode, 'introspection');
  // a forged nonce header on a non Microsoft JWT gives no claim from the token either
  const kc = openid();
  const forged = sign(rsaKey('kc-1'), kcClaims({ name: 'Mallory' }), { nonce: 'x' });
  const downgraded = login(kc.jwt, forged, introspection());
  assert.equal(downgraded.mode, 'introspection');
  assert.equal(downgraded.claims.name, undefined);
});

test('url policy', () => {
  const { jwt } = openid();
  assert.equal(jwt.isAllowedUrl('https://login.microsoftonline.com/common/discovery/v2.0/keys'), true);
  assert.equal(jwt.isAllowedUrl('http://127.0.0.1:8080/certs'), true);
  assert.equal(jwt.isAllowedUrl('http://evil.example.com/certs'), false);
  assert.equal(jwt.isAllowedUrl('https://user@evil.example.com/certs'), false);
  assert.equal(jwt.isAllowedUrl('file:///etc/passwd'), false);
  assert.equal(jwt.isAllowedUrl(null), false);
});
