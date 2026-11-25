// Runs js/jwt_verify.js in a real Rhino engine with its Java platform (Base64, KeyFactory, Signature,
// MessageDigest) against tokens signed by Node. Only fetch and symbols are stubbed.
// Rhino jars: RHINO_JARS (classpath) or the Gradle caches; skipped when java or Rhino is not available.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { spawnSync } = require('node:child_process');

const project = path.resolve(__dirname, '../..');
const helperPath = path.join(project, 'js/jwt_verify.js');
const scopePath = path.join(project, 'js/openid_scope.js');

function findJars(root, names) {
  const found = [];
  const walk = (dir, depth) => {
    if (depth > 8 || found.length === names.length) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full, depth + 1);
      else if (names.includes(entry.name) && !found.some((jar) => path.basename(jar) === entry.name)) found.push(full);
    }
  };
  walk(root, 0);
  return found.length === names.length ? found.join(path.delimiter) : null;
}

function classpaths() {
  if (process.env.RHINO_JARS) return [process.env.RHINO_JARS];
  const gradle = path.join(os.homedir(), '.gradle');
  return [
    findJars(path.join(gradle, 'caches/modules-2/files-2.1/org.mozilla'), ['rhino-1.9.1.jar', 'rhino-tools-1.9.1.jar']),
    findJars(path.join(gradle, 'wrapper/dists'), ['rhino-1.7.10.jar']),
  ].filter(Boolean);
}

const javaAvailable = spawnSync('java', ['-version']).status === 0;

const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);

function key(type, kid, options) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync(type, options);
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig' } };
}

function sign(k, claims) {
  const alg = k.jwk.kty === 'EC' ? 'ES256' : 'RS256';
  const input = b64({ alg, kid: k.kid, typ: 'JWT' }) + '.' + b64(claims);
  const signature = alg === 'ES256'
    ? crypto.sign('sha256', Buffer.from(input), { key: k.privateKey, dsaEncoding: 'ieee-p1363' })
    : crypto.sign('sha256', Buffer.from(input), k.privateKey);
  return input + '.' + signature.toString('base64url');
}

function tamper(token) {
  const [header, payload, signature] = token.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  claims.sub = 'someone-else';
  return header + '.' + b64(claims) + '.' + signature;
}

function fixture() {
  const google = key('rsa', 'g1', { modulusLength: 2048 });
  const weak = key('rsa', 'weak', { modulusLength: 1024 });
  const ms = key('rsa', 'm1', { modulusLength: 2048 });
  const kc = key('ec', 'k1', { namedCurve: 'P-256' });
  const tenant = '11111111-2222-3333-4444-555555555555';
  const accessToken = 'EwB-graph-access-token';
  const digest = crypto.createHash('sha256').update(accessToken).digest();
  const issuerMs = 'https://login.microsoftonline.com/' + tenant + '/v2.0';
  const kcIssuer = 'https://idp.example.com/realms/c8o';
  const googleClaims = {
    iss: 'https://accounts.google.com', aud: 'g-client', sub: '42', email: 'elodie@example.com',
    name: 'Élodie 日本', iat: now(), exp: now() + 600,
  };
  const msClaims = {
    iss: issuerMs, aud: 'ms-client', tid: tenant, sub: 'pairwise', at_hash: digest.subarray(0, 16).toString('base64url'),
    iat: now(), exp: now() + 600,
  };
  const kcClaims = { iss: kcIssuer, aud: 'account', azp: 'kc-client', sub: 'user-1', iat: now(), exp: now() + 300 };
  const graphAccessToken = b64({ alg: 'RS256', kid: 'graph', nonce: 'abc' }) + '.' + b64({ iss: 'https://sts.windows.net/' + tenant + '/', sub: 'x', exp: now() + 600 }) + '.c2ln';
  const graphDigest = crypto.createHash('sha256').update(graphAccessToken).digest();
  return {
    symbols: {
      'lib_oauth.google.clientid': 'g-client',
      'lib_oauth.azuread.clientid': 'ms-client',
      'lib_oauth.azuread.tenantid': tenant,
      'lib_oauth.openid.clientid': 'kc-client',
      'lib_oauth.openid.groups_claim': 'realm_access.roles',
    },
    documents: {
      'https://accounts.google.com/.well-known/openid-configuration': { issuer: 'https://accounts.google.com', jwks_uri: 'https://google/certs' },
      'https://google/certs': { keys: [google.jwk, weak.jwk] },
      ['https://login.microsoftonline.com/' + tenant + '/v2.0/.well-known/openid-configuration']: { issuer: issuerMs, jwks_uri: 'https://ms/keys' },
      'https://ms/keys': { keys: [ms.jwk] },
      [kcIssuer + '/.well-known/openid-configuration']: { issuer: kcIssuer, jwks_uri: 'https://kc/certs' },
      'https://kc/certs': { keys: [kc.jwk] },
    },
    accessToken,
    kcIssuer,
    tokens: {
      google: sign(google, googleClaims),
      googleTampered: tamper(sign(google, googleClaims)),
      googleWeakKey: sign(weak, googleClaims),
      googleExpired: sign(google, { ...googleClaims, exp: now() - 400 }),
      azure: sign(ms, msClaims),
      openid: sign(kc, kcClaims),
      openidRoles: sign(kc, { ...kcClaims, realm_access: { roles: ['editor', ' editor ', 'auditor'] } }),
      openidIdToken: sign(kc, { iss: kcIssuer, aud: 'kc-client', sub: 'user-1', at_hash: crypto.createHash('sha256').update('opaque-token').digest().subarray(0, 16).toString('base64url'), iat: now(), exp: now() + 300, realm_access: { roles: ['from-id-token'] } }),
      openidTampered: tamper(sign(kc, kcClaims)),
      graphAccessToken,
      graphIdToken: sign(ms, { ...msClaims, aud: 'kc-client', sub: 'user-1', at_hash: graphDigest.subarray(0, 16).toString('base64url') }),
    },
  };
}

const script = `
load(arguments[0]);
load(arguments[2]);
var fixture = JSON.parse(readFile(arguments[1]));
var platform = libOAuthJwt.javaPlatform();
platform.fetch = function (url) {
  if (!fixture.documents.hasOwnProperty(url)) throw new Error("404 " + url);
  return JSON.stringify(fixture.documents[url]);
};
platform.symbol = function (name) { return fixture.symbols[name] || ""; };
libOAuthJwt.platform = platform;
var t = fixture.tokens;
var introspection = { active: true, sub: "user-1", iss: fixture.kcIssuer, client_id: "" };
// as a JsonSourceStep would produce it (JSON parsed outside the helper, untyped values)
var opaqueIntrospection = JSON.parse('{"active": "true", "sub": "user-1", "exp": "' + (Math.floor(Date.now() / 1000) + 60) + '", "aud": ["account", "kc-client"]}');
print(JSON.stringify({
  cacheWithoutEngine: platform.cacheGet("x"),
  google: libOAuthJwt.verifyGoogleIdToken(t.google),
  googleTampered: libOAuthJwt.verifyGoogleIdToken(t.googleTampered),
  googleWeakKey: libOAuthJwt.verifyGoogleIdToken(t.googleWeakKey),
  googleExpired: libOAuthJwt.verifyGoogleIdToken(t.googleExpired),
  azure: libOAuthJwt.verifyAzureAdIdToken(t.azure, fixture.accessToken),
  azureOtherAccessToken: libOAuthJwt.verifyAzureAdIdToken(t.azure, "other"),
  openid: libOAuthJwt.verifyOpenIdLogin(t.openid, introspection, ""),
  openidTampered: libOAuthJwt.verifyOpenIdLogin(t.openidTampered, introspection, ""),
  opaque: libOAuthJwt.verifyOpenIdLogin("2YotnFZFEjr1zCsicMWpAA", opaqueIntrospection, ""),
  opaqueInactive: libOAuthJwt.verifyOpenIdLogin("2YotnFZFEjr1zCsicMWpAA", JSON.parse('{"active": false, "sub": "user-1", "client_id": "kc-client"}'), ""),
  graph: libOAuthJwt.verifyOpenIdLogin(t.graphAccessToken, { active: true, sub: "user-1" }, t.graphIdToken),
  graphOtherAccessToken: libOAuthJwt.verifyOpenIdLogin(t.openid, introspection, t.graphIdToken),
  okType: typeof libOAuthJwt.verifyGoogleIdToken(t.google).ok,
  groupsJwt: libOAuthJwt.openIdGroups(libOAuthJwt.verifyOpenIdLogin(t.openidRoles, introspection, ""), t.openidRoles, introspection, ""),
  groupsIdToken: libOAuthJwt.openIdGroups(libOAuthJwt.verifyOpenIdLogin("opaque-token", opaqueIntrospection, t.openidIdToken), "opaque-token", JSON.parse('{"active": "true", "sub": "user-1", "iss": "' + fixture.kcIssuer + '", "aud": ["kc-client"]}'), t.openidIdToken),
  groupsTampered: libOAuthJwt.openIdGroups(libOAuthJwt.verifyOpenIdLogin("opaque-token", opaqueIntrospection, ""), "opaque-token", JSON.parse('{"active": "true", "sub": "user-1", "iss": "' + fixture.kcIssuer + '", "aud": ["kc-client"]}'), t.openidTampered),
  scopeDefault: libOAuthOpenIdScope.resolve(""),
  scopeSymbol: libOAuthOpenIdScope.resolve("profile, email groups&prompt=none")
}));
`;

const paths = javaAvailable ? classpaths() : [];

test('rhino: java platform verifies real signatures', { skip: paths.length === 0 && 'java or Rhino jars not available' }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lib-oauth-jwt-'));
  try {
    const data = fixture();
    fs.writeFileSync(path.join(dir, 'fixture.json'), JSON.stringify(data));
    fs.writeFileSync(path.join(dir, 'run.js'), script);
    for (const classpath of paths) {
      const run = spawnSync('java', ['-cp', classpath, 'org.mozilla.javascript.tools.shell.Main', '-version', '200',
        path.join(dir, 'run.js'), helperPath, path.join(dir, 'fixture.json'), scopePath], { encoding: 'utf8' });
      assert.equal(run.status, 0, classpath + '\n' + run.stderr + run.stdout);
      const r = JSON.parse(run.stdout.trim().split('\n').pop());
      const label = path.basename(classpath.split(path.delimiter)[0]);
      assert.equal(r.cacheWithoutEngine, null, label);
      assert.equal(r.okType, 'boolean', label);
      assert.equal(r.google.ok, true, label + ' ' + r.google.error);
      assert.equal(r.google.claims.name, 'Élodie 日本', label);
      assert.match(r.googleTampered.error, /signature is invalid/, label);
      assert.match(r.googleWeakKey.error, /signature is invalid/, label);
      assert.match(r.googleExpired.error, /expired/, label);
      assert.equal(r.azure.ok, true, label + ' ' + r.azure.error);
      assert.match(r.azureOtherAccessToken.error, /at_hash/, label);
      assert.equal(r.openid.ok, true, label + ' ' + r.openid.error);
      assert.match(r.openidTampered.error, /signature is invalid/, label);
      assert.equal(r.opaque.ok, true, label + ' ' + r.opaque.error);
      assert.equal(r.opaque.mode, 'introspection', label);
      assert.match(r.opaqueInactive.error, /not active/, label);
      assert.equal(r.graph.ok, true, label + ' ' + r.graph.error);
      assert.equal(r.graph.mode, 'id_token', label);
      assert.equal(r.graphOtherAccessToken.mode, 'jwt', label + ' a verifiable JWT keeps the JWT path');
      assert.deepEqual([r.groupsJwt.state, r.groupsJwt.source, r.groupsJwt.groups], ['present', 'access_token', ['editor', 'auditor']], label);
      assert.deepEqual([r.groupsIdToken.state, r.groupsIdToken.source, r.groupsIdToken.groups], ['present', 'id_token', ['from-id-token']], label + ' ' + JSON.stringify(r.groupsIdToken.warnings));
      assert.equal(r.groupsTampered.state, 'missing', label);
      assert.match(r.groupsTampered.warnings[0], /id_token not used/, label);
      assert.equal(r.scopeDefault.encoded, 'openid%20profile%20email', label);
      assert.equal(r.scopeSymbol.encoded, 'openid%20profile%20email%20groups%26prompt%3Dnone', label);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
