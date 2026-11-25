// Scopes of the OpenID sign-in (js/openid_scope.js, symbol lib_oauth.openid.scope, OpenIDScope of GetOAuthCredentials):
// the scopes of the earlier versions by default, "openid" always requested, a value URL encoded so that no scope can
// add a parameter to the authorization URL the OAuth action builds, an invalid value ignored.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const project = path.resolve(__dirname, '../..');
const sandbox = {};
vm.runInNewContext(fs.readFileSync(path.join(project, 'js/openid_scope.js'), 'utf8'), sandbox, { filename: 'openid_scope.js' });
const { libOAuthOpenIdScope: scope } = sandbox;
const resolve = (raw) => JSON.parse(JSON.stringify(scope.resolve(raw)));

// the authorization URL of the OAuth action of the Mobile Builder (provider openid), scope added as it is
const authorizeUrl = (encoded) => new URL('https://idp.example.com/auth?client_id=c8o&response_type=id_token+token&scope=' + encoded + '&state=c8ocsrf&nonce=1');

test('without the symbol: the scopes of the earlier versions', () => {
  for (const raw of [undefined, null, '', '   ', '${lib_oauth.openid.scope}']) {
    assert.deepEqual(resolve(raw), {
      scopes: ['openid', 'profile', 'email'], scope: 'openid profile email', encoded: 'openid%20profile%20email', source: 'default', warning: '',
    }, String(raw));
  }
  assert.equal(scope.DEFAULT_SCOPE, 'openid profile email');
  // the same scope parameter as the former plain value of the C8Oforms login page
  assert.equal(authorizeUrl(resolve('').encoded).searchParams.get('scope'), 'openid profile email');
});

test('the symbol: spaces or commas, openid always first, duplicates removed', () => {
  assert.deepEqual(resolve('openid profile email groups'), {
    scopes: ['openid', 'profile', 'email', 'groups'], scope: 'openid profile email groups', encoded: 'openid%20profile%20email%20groups', source: 'symbol', warning: '',
  });
  assert.deepEqual(resolve(' profile,email ,  roles\tprofile\n').scopes, ['openid', 'profile', 'email', 'roles']);
  assert.deepEqual(resolve('email').scopes, ['openid', 'email']);
  assert.deepEqual(resolve('openid').scopes, ['openid']);
  assert.deepEqual(resolve('api://c8oforms/.default offline_access').scopes, ['openid', 'api://c8oforms/.default', 'offline_access']);
});

test('a scope never adds a parameter to the authorization URL', () => {
  for (const raw of ['openid&prompt=none', 'x#fragment', 'a+b', 'redirect_uri=https://evil.example.com', 'a%26b', 'a?b', "it's"]) {
    const r = resolve(raw);
    assert.equal(r.source, 'symbol', raw);
    const url = authorizeUrl(r.encoded);
    assert.deepEqual([...url.searchParams.keys()], ['client_id', 'response_type', 'scope', 'state', 'nonce'], raw);
    assert.equal(url.searchParams.get('scope'), r.scope, raw);
    assert.equal(url.hash, '', raw);
    assert.doesNotMatch(r.encoded, /[&#=?+ ]/, raw);
  }
});

test('an invalid value is ignored with a warning: the default scopes are requested', () => {
  const invalid = ['profile "email"', 'back\\slash', 'ctrl\u0001', 'é', 'x'.repeat(2049), Array.from({ length: 50 }, (_, i) => 's' + i).join(' ')];
  for (const raw of invalid) {
    const r = resolve(raw);
    assert.equal(r.source, 'default', raw.slice(0, 30));
    assert.equal(r.encoded, 'openid%20profile%20email');
    assert.match(r.warning, /symbol lib_oauth\.openid\.scope/);
  }
  // 49 scopes plus openid is the maximum
  assert.equal(resolve(Array.from({ length: 49 }, (_, i) => 's' + i).join(' ')).source, 'symbol');
});
