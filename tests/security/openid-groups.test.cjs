// Groups of an OpenID user (js/jwt_verify.js openIdGroups, symbol lib_oauth.openid.groups_claim): read only from
// verified sources (id_token verified here or by the Microsoft rules, verified JWT access token or introspection
// response, userinfo of the provider for the same sub), nothing without the symbol, no group when the claim is missing
// or invalid, never a token in a warning. Synthetic keys and tokens signed here; no identity provider is called.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const project = path.resolve(__dirname, '../..');
const helper = fs.readFileSync(path.join(project, 'js/jwt_verify.js'), 'utf8');

const KC = 'https://idp.example.com/realms/c8o';
const KC_USERINFO = KC + '/protocol/openid-connect/userinfo';
const TENANT = '11111111-2222-3333-4444-555555555555';
const MS = 'https://login.microsoftonline.com/';
const ENTRA = MS + TENANT + '/v2.0';

const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const plain = (value) => JSON.parse(JSON.stringify(value));
const now = () => Math.floor(Date.now() / 1000);

function key(type, kid, options) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync(type, options);
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig' } };
}

function sign(k, claims, header = {}) {
  const alg = k.jwk.kty === 'EC' ? 'ES256' : 'RS256';
  const input = b64({ typ: 'JWT', alg, kid: k.kid, ...header }) + '.' + b64(claims);
  const signature = alg === 'ES256'
    ? crypto.sign('sha256', Buffer.from(input), { key: k.privateKey, dsaEncoding: 'ieee-p1363' })
    : crypto.sign('sha256', Buffer.from(input), k.privateKey);
  return input + '.' + signature.toString('base64url');
}

function atHash(accessToken) {
  const digest = crypto.createHash('sha256').update(accessToken, 'ascii').digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

const kcKey = key('ec', 'kc-1', { namedCurve: 'P-256' });
const msKey = key('rsa', 'ms-1', { modulusLength: 2048 });
const graphKey = key('rsa', 'graph-1', { modulusLength: 2048 });

// Node platform of the helper; userinfo answers only to the bearer token it expects.
function load({ symbols = {}, documents = {}, userinfo = {} } = {}) {
  const cache = new Map();
  const calls = [];
  const platform = {
    now: () => Date.now(),
    decodeBase64Url(text) {
      if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not base64url');
      return Buffer.from(text, 'base64url');
    },
    utf8: (data) => new TextDecoder('utf-8', { fatal: true }).decode(data),
    verifySignature(alg, jwk, input, signature) {
      const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      return alg.startsWith('ES')
        ? crypto.verify('sha256', Buffer.from(input, 'ascii'), { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)
        : crypto.verify('sha256', Buffer.from(input, 'ascii'), publicKey, signature);
    },
    accessTokenHash: (alg, accessToken) => atHash(accessToken),
    fetch(url) {
      calls.push({ url });
      if (!(url in documents)) throw new Error('404');
      return JSON.stringify(documents[url]);
    },
    fetchWithBearer(url, accessToken) {
      calls.push({ url, bearer: accessToken });
      const answer = userinfo[url];
      if (answer == null || answer.token !== accessToken) throw new Error('HTTP 401 from ' + url);
      return typeof answer.body === 'string' ? answer.body : JSON.stringify(answer.body);
    },
    cacheGet: (k) => (cache.has(k) ? cache.get(k) : null),
    cachePut: (k, v) => cache.set(k, v),
    symbol: (name) => symbols[name] || '',
  };
  const sandbox = {};
  vm.runInNewContext(helper, sandbox, { filename: 'jwt_verify.js' });
  sandbox.libOAuthJwt.platform = platform;
  return { jwt: sandbox.libOAuthJwt, calls, documents, userinfo };
}

function keycloak({ symbols = {}, userinfo = {}, discovery = {} } = {}) {
  return load({
    symbols: { 'lib_oauth.openid.clientid': 'c8o-client', 'lib_oauth.openid.groups_claim': 'groups', ...symbols },
    documents: {
      [KC + '/.well-known/openid-configuration']: {
        issuer: KC, jwks_uri: KC + '/protocol/openid-connect/certs', userinfo_endpoint: KC_USERINFO, ...discovery,
      },
      [KC + '/protocol/openid-connect/certs']: { keys: [kcKey.jwk] },
    },
    userinfo,
  });
}

const OPAQUE = '2YotnFZFEjr1zCsicMWpAA';
const introspection = (extra = {}) => ({ active: true, sub: 'user-1', iss: KC, client_id: 'c8o-client', ...extra });
const accessClaims = (extra = {}) => ({ iss: KC, aud: 'account', azp: 'c8o-client', sub: 'user-1', iat: now(), exp: now() + 300, ...extra });
const idClaims = (accessToken, extra = {}) => ({
  iss: KC, aud: 'c8o-client', sub: 'user-1', at_hash: atHash(accessToken), nonce: '1731760000000', iat: now(), exp: now() + 300, ...extra,
});

// what loginOpenIDWithAccessToken does: verifyOpenIdLogin, then openIdGroups
function groupsOf(env, accessToken, introspected, idToken = '') {
  const verification = env.jwt.verifyOpenIdLogin(accessToken, introspected, idToken);
  assert.equal(verification.ok, true, verification.error);
  return plain(env.jwt.openIdGroups(verification, accessToken, introspected, idToken));
}

test('without lib_oauth.openid.groups_claim nothing is read and nothing is fetched', () => {
  const env = keycloak({ symbols: { 'lib_oauth.openid.groups_claim': '' } });
  const access = sign(kcKey, accessClaims({ groups: ['admins'] }));
  assert.deepEqual(groupsOf(env, access, introspection({ groups: ['admins'] })), { enabled: false });
  assert.deepEqual(groupsOf(env, OPAQUE, introspection({ groups: ['admins'] })), { enabled: false });
  assert.equal(env.calls.filter((call) => call.bearer).length, 0);
});

test('id_token: groups of a verified id_token bound to the access token', () => {
  const env = keycloak();
  const id = sign(kcKey, idClaims(OPAQUE, { groups: ['/staff/hr', 'sales'] }));
  const result = groupsOf(env, OPAQUE, introspection({ groups: ['other'] }), id);
  assert.deepEqual(result, { enabled: true, claim: 'groups', state: 'present', groups: ['/staff/hr', 'sales'], source: 'id_token', warnings: [] });
  // the first source holding the claim decides, even with no group in it
  const empty = sign(kcKey, idClaims(OPAQUE, { groups: [] }));
  const none = groupsOf(env, OPAQUE, introspection({ groups: ['admins'] }), empty);
  assert.equal(none.state, 'present');
  assert.deepEqual(none.groups, []);
  assert.equal(none.source, 'id_token');
});

test('id_token: a forged, foreign or unbound id_token never gives its groups', () => {
  const env = keycloak();
  const attacker = key('ec', 'kc-1', { namedCurve: 'P-256' });
  const genuine = sign(kcKey, idClaims(OPAQUE, { groups: ['users'] }));
  const [header, , signature] = genuine.split('.');
  const cases = {
    'signature is invalid': [
      sign(attacker, idClaims(OPAQUE, { groups: ['admins'] })),
      header + '.' + b64(idClaims(OPAQUE, { groups: ['admins'] })) + '.' + signature,
    ],
    'algorithm none': [b64({ alg: 'none' }) + '.' + b64(idClaims(OPAQUE, { groups: ['admins'] })) + '.AA'],
    'not a signed compact JWT': [b64({ alg: 'none' }) + '.' + b64(idClaims(OPAQUE, { groups: ['admins'] })) + '.'],
    'at_hash': [sign(kcKey, idClaims('another-access-token', { groups: ['admins'] })), sign(kcKey, idClaims(OPAQUE, { groups: ['admins'], at_hash: undefined }))],
    'audience': [sign(kcKey, idClaims(OPAQUE, { groups: ['admins'], aud: 'other-client' }))],
    'issuer': [sign(kcKey, idClaims(OPAQUE, { groups: ['admins'], iss: 'https://evil.example.com' }))],
    'expired': [sign(kcKey, idClaims(OPAQUE, { groups: ['admins'], exp: now() - 600 }))],
    'sub does not match': [sign(kcKey, idClaims(OPAQUE, { groups: ['admins'], sub: 'user-2' }))],
  };
  for (const [error, tokens] of Object.entries(cases)) {
    for (const id of tokens) {
      const result = groupsOf(env, OPAQUE, introspection({ groups: ['users'] }), id);
      assert.equal(result.source, 'introspection', error);
      assert.deepEqual(result.groups, ['users'], error);
      assert.ok(result.warnings.some((w) => w.startsWith('id_token not used:') && w.includes(error)), error + ' ' + JSON.stringify(result.warnings));
    }
  }
});

test('access token: groups of a verified JWT access token, never of a forged or unverifiable one', () => {
  const env = keycloak();
  const access = sign(kcKey, accessClaims({ groups: ['sales'] }));
  const result = groupsOf(env, access, introspection({ groups: ['introspected'] }));
  assert.equal(result.source, 'access_token');
  assert.deepEqual(result.groups, ['sales']);
  // a forged JWT is refused by verifyOpenIdLogin: no login, so no groups
  const [h, , s] = access.split('.');
  const forged = h + '.' + b64(accessClaims({ groups: ['admins'] })) + '.' + s;
  assert.equal(env.jwt.verifyOpenIdLogin(forged, introspection(), '').ok, false);
  // a nonce header (unverifiable, Microsoft rules) downgrades to the introspection response: the token claims are not used
  const unverifiable = sign(key('ec', 'kc-1', { namedCurve: 'P-256' }), accessClaims({ groups: ['admins'] }), { nonce: 'x' });
  const downgraded = groupsOf(env, unverifiable, introspection());
  assert.equal(downgraded.state, 'missing');
  assert.deepEqual(downgraded.groups, []);
  assert.notEqual(downgraded.source, 'access_token');
});

test('introspection: groups of the response of the trusted introspection endpoint (opaque token)', () => {
  const env = keycloak({ symbols: { 'lib_oauth.openid.groups_claim': 'roles' } });
  const result = groupsOf(env, OPAQUE, introspection({ roles: 'editor' }));
  assert.deepEqual([result.state, result.source, result.groups], ['present', 'introspection', ['editor']]);
  // an XML round trip (JsonSourceStep) gives {item: [...]}
  assert.deepEqual(groupsOf(env, OPAQUE, introspection({ roles: { item: ['a', 'b'] } })).groups, ['a', 'b']);
  assert.deepEqual(env.calls.filter((call) => call.bearer), [], 'no userinfo call when a token holds the claim');
});

test('userinfo: read with the access token when no token holds the claim, for the same sub only', () => {
  const access = sign(kcKey, accessClaims());
  const env = keycloak({ userinfo: { [KC_USERINFO]: { token: access, body: { sub: 'user-1', groups: ['support'] } } } });
  const result = groupsOf(env, access, introspection());
  assert.deepEqual([result.state, result.source, result.groups], ['present', 'userinfo', ['support']]);
  assert.deepEqual(env.calls.filter((call) => call.bearer).map((call) => call.url), [KC_USERINFO]);
  // another user, a JWT answer, an error, no endpoint, a plain http endpoint: no group
  const refused = [
    [{ [KC_USERINFO]: { token: access, body: { sub: 'user-2', groups: ['admins'] } } }, {}, /userinfo sub does not match/],
    [{ [KC_USERINFO]: { token: access, body: sign(kcKey, { sub: 'user-1', groups: ['admins'] }) } }, {}, /userinfo response is not valid JSON/],
    [{ [KC_USERINFO]: { token: 'other', body: { sub: 'user-1', groups: ['admins'] } } }, {}, /HTTP 401/],
    [{}, { userinfo_endpoint: undefined }, /no userinfo_endpoint/],
    [{ 'http://idp.example.com/userinfo': { token: access, body: { sub: 'user-1', groups: ['admins'] } } }, { userinfo_endpoint: 'http://idp.example.com/userinfo' }, /refusing to call/],
  ];
  for (const [userinfo, discovery, pattern] of refused) {
    const r = groupsOf(keycloak({ userinfo, discovery }), access, introspection());
    assert.equal(r.state, 'missing', String(pattern));
    assert.deepEqual(r.groups, []);
    assert.ok(r.warnings.some((w) => pattern.test(w)), String(pattern) + ' ' + JSON.stringify(r.warnings));
  }
});

test('missing claim: the user gets no group, with a warning', () => {
  const access = sign(kcKey, accessClaims());
  const env = keycloak({ userinfo: { [KC_USERINFO]: { token: access, body: { sub: 'user-1' } } } });
  const result = groupsOf(env, access, introspection());
  assert.equal(result.state, 'missing');
  assert.deepEqual(result.groups, []);
  assert.equal(result.source, '');
  assert.match(result.warnings.at(-1), /claim groups not found, the user gets no group/);
  // the login itself is not refused
  assert.equal(env.jwt.verifyOpenIdLogin(access, introspection(), '').ok, true);
});

test('invalid claim values and names give no group', () => {
  const env = keycloak();
  for (const value of [{ admin: true }, [1, 2], ['ok', { x: 1 }], 42, true, Array.from({ length: 201 }, (_, i) => 'g' + i)]) {
    const r = groupsOf(env, OPAQUE, introspection({ groups: value }));
    assert.equal(r.state, 'missing', JSON.stringify(value).slice(0, 40));
    assert.deepEqual(r.groups, []);
    assert.equal(r.source, 'introspection');
    assert.match(r.warnings[0], /the user gets no group/);
  }
  for (const name of ['two words', 'x'.repeat(257), 'tab\tname']) {
    const r = groupsOf(keycloak({ symbols: { 'lib_oauth.openid.groups_claim': name } }), OPAQUE, introspection({ [name]: ['admins'] }));
    assert.equal(r.state, 'missing', name.slice(0, 20));
    assert.match(r.warnings[0], /not a claim name/);
  }
});

test('claim values: trimmed, unique, control characters and long names dropped, nested paths', () => {
  const { jwt } = keycloak();
  const read = (claims, name = 'groups') => plain(jwt.groupsFromClaims(claims, name));
  assert.deepEqual(read({ groups: [' sales ', 'sales', '', '  ', 'hr'] }), { found: true, groups: ['sales', 'hr'], dropped: 0 });
  assert.deepEqual(read({ groups: ['ok', 'bad\nname', 'x'.repeat(257), 'tab\tname'] }), { found: true, groups: ['ok'], dropped: 3 });
  assert.deepEqual(read({ groups: '' }), { found: true, groups: [], dropped: 0 });
  assert.deepEqual(read({ groups: null }), { found: false });
  assert.deepEqual(read({}), { found: false });
  assert.deepEqual(read({ realm_access: { roles: ['admin', 'user'] } }, 'realm_access.roles'), { found: true, groups: ['admin', 'user'], dropped: 0 });
  // a claim whose name has dots wins over the path
  assert.deepEqual(read({ 'https://example.com/groups': ['a'], https: { x: 1 } }, 'https://example.com/groups').groups, ['a']);
  for (const claims of [{ realm_access: ['roles'] }, { realm_access: null }, { realm_access: { other: [] } }, { realm_access: 'roles' }]) {
    assert.deepEqual(read(claims, 'realm_access.roles'), { found: false }, JSON.stringify(claims));
  }
  assert.equal(read({ 'a..b': ['x'] }, 'a..b').groups[0], 'x');
  assert.deepEqual(read({ a: { '': { b: ['x'] } } }, 'a..b'), { found: false });
  // prototype keys are not claims
  assert.deepEqual(read({}, 'constructor'), { found: false });
  assert.deepEqual(read({}, '__proto__'), { found: false });
  assert.deepEqual(read({ groups: ['x'] }, 'groups.length'), { found: false });
});

test('microsoft: groups of the verified id_token, never of the Graph access token', () => {
  const graph = sign(graphKey, {
    iss: 'https://sts.windows.net/' + TENANT + '/', aud: '00000003-0000-0000-c000-000000000000', appid: 'entra-client',
    tid: TENANT, sub: 'graph-pairwise', groups: ['forged-admins'], roles: ['Global.Admin'], exp: now() + 3600,
  }, { nonce: 'abcdef' });
  const idToken = (extra = {}) => sign(msKey, {
    iss: ENTRA, aud: 'entra-client', tid: TENANT, sub: 'id-pairwise', at_hash: atHash(graph), iat: now(), exp: now() + 3600, ...extra,
  });
  const env = (symbols = {}, userinfo = {}) => load({
    symbols: { 'lib_oauth.openid.clientid': 'entra-client', 'lib_oauth.openid.groups_claim': 'groups', ...symbols },
    documents: {
      [ENTRA + '/.well-known/openid-configuration']: { issuer: ENTRA, jwks_uri: MS + TENANT + '/discovery/v2.0/keys', userinfo_endpoint: 'https://graph.microsoft.com/oidc/userinfo' },
      [MS + TENANT + '/discovery/v2.0/keys']: { keys: [msKey.jwk] },
    },
    userinfo,
  });
  const introspected = { active: true, sub: 'id-pairwise', client_id: 'entra-client' };
  const groupIds = ['6c1e0b8a-0000-4000-8000-000000000001', '6c1e0b8a-0000-4000-8000-000000000002'];
  const present = groupsOf(env(), graph, introspected, idToken({ groups: groupIds }));
  assert.deepEqual([present.state, present.source, present.groups], ['present', 'id_token', groupIds]);
  assert.deepEqual(groupsOf(env({ 'lib_oauth.openid.groups_claim': 'roles' }), graph, introspected, idToken({ roles: ['Forms.Editor'] })).groups, ['Forms.Editor']);
  // overage: the groups are left out of the id_token; the userinfo of Microsoft has none either
  const overage = groupsOf(env({}, { 'https://graph.microsoft.com/oidc/userinfo': { token: graph, body: { sub: 'id-pairwise' } } }), graph, introspected, idToken({ hasgroups: true }));
  assert.equal(overage.state, 'missing');
  assert.deepEqual(overage.groups, []);
  assert.ok(overage.warnings.some((w) => /left the groups out/.test(w)), JSON.stringify(overage.warnings));
  // without id_token: introspection only, the Graph token is never read
  const noIdToken = groupsOf(env(), graph, introspected, '');
  assert.equal(noIdToken.state, 'missing');
  assert.ok(!JSON.stringify(noIdToken).includes('forged-admins'));
});

test('an unverified login gives no group, and no warning holds a token', () => {
  const env = keycloak();
  const access = sign(kcKey, accessClaims({ groups: ['admins'] }));
  for (const verification of [null, { ok: false, error: 'x' }, { ok: true, mode: 'jwt', claims: { groups: ['admins'] } }]) {
    const introspected = verification && verification.ok ? null : introspection();
    const r = plain(env.jwt.openIdGroups(verification, access, introspected, ''));
    assert.equal(r.state, 'missing');
    assert.deepEqual(r.groups, []);
    assert.match(r.warnings[0], /not verified/);
  }
  const id = sign(key('ec', 'kc-1', { namedCurve: 'P-256' }), idClaims(access, { groups: ['admins'] }));
  const r = groupsOf(env, access, introspection(), id);
  for (const warning of r.warnings) {
    for (const token of [access, id, ...access.split('.'), ...id.split('.')]) {
      assert.ok(!warning.includes(token), warning);
    }
  }
});
