// Static checks of the login sequences: every JWT is verified by js/jwt_verify.js before a claim,
// the session token or the authenticated user is set, and the public interface stays the same.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const project = path.resolve(__dirname, '../..');
const sequencesDir = path.join(project, '_c8oProject/sequences');
const read = (name) => fs.readFileSync(path.join(sequencesDir, name + '.yaml'), 'utf8');

// Same decoding as the engine YamlConverter.readYalmText for `key: value` and `key: |` blocks.
function properties(yaml, key) {
  const lines = yaml.split('\n');
  const values = [];
  for (let i = 0; i < lines.length; i++) {
    const match = new RegExp('^( *)' + key + ': (.*)$').exec(lines[i]);
    if (!match) continue;
    let value = match[2];
    if (value === '|') {
      const indent = match[1] + '  ';
      const block = [];
      while (i + 1 < lines.length && lines[i + 1].startsWith(indent)) block.push(lines[++i].slice(indent.length));
      value = block.join('\n');
    }
    if (value.startsWith("'")) value = value.slice(1, -1).replace(/''/g, "'");
    values.push(value);
  }
  return values;
}

function indexOfBean(yaml, name) {
  const index = yaml.indexOf(name);
  assert.notEqual(index, -1, name + ' not found');
  return index;
}

function assertOrder(yaml, names) {
  for (let i = 1; i < names.length; i++) {
    assert.ok(indexOfBean(yaml, names[i - 1]) < indexOfBean(yaml, names[i]), names[i - 1] + ' must run before ' + names[i]);
  }
}

const sequences = fs.readdirSync(sequencesDir).filter((f) => f.endsWith('.yaml')).map((f) => f.slice(0, -5));

test('no sequence decodes a JWT payload by itself', () => {
  for (const name of sequences) {
    const yaml = read(name);
    assert.doesNotMatch(yaml, /split\((''|")\.(''|")\)/, name);
    assert.doesNotMatch(yaml, /Base64\.decodeToString|atob\s*=|atob\(/, name);
  }
});

test('step scripts compile and contain no symbol placeholder', () => {
  for (const name of sequences) {
    const yaml = read(name);
    for (const code of properties(yaml, 'expression').concat(properties(yaml, 'condition'))) {
      assert.doesNotMatch(code, /\$\{/, name);
      assert.doesNotThrow(() => new vm.Script('(function () {\n' + code + '\n})'), name + ':\n' + code);
    }
  }
});

test('bean priorities are unique in the project', () => {
  const ids = [];
  for (const dir of ['sequences', 'connectors']) {
    for (const file of fs.readdirSync(path.join(project, '_c8oProject', dir))) {
      const yaml = fs.readFileSync(path.join(project, '_c8oProject', dir, file), 'utf8');
      for (const match of yaml.matchAll(/\[[A-Za-z]+\.[A-Za-z]+-(\d+)\]/g)) ids.push(match[1]);
    }
  }
  assert.deepEqual(ids.filter((id, i) => ids.indexOf(id) !== i), []);
});

test('google: id_token verified before login, session token and claims', () => {
  const yaml = read('loginGoogleWithCode');
  const [verify] = properties(yaml, 'expression').filter((code) => code.includes('verifyGoogleIdToken'));
  assert.match(verify, /include\("js\/jwt_verify\.js"\)/);
  assert.match(verify, /id_token_verified = verification\.ok/);
  assert.match(yaml, /condition: '!id_token_verified'/);
  assertOrder(yaml, [
    '↓id_token [steps.SimpleSourceStep-1572733085248]',
    '↓VerifyIdToken [steps.SimpleStep-1790600000001]',
    '↓RejectUnverifiedIdToken [steps.IfStep-1790600000002]',
    '↓login [steps.XMLElementStep-1602831342500]',
    '↓SetOAuthTokenInSession [steps.SessionSetStep-1572768463214]',
    '↓DecodeJWT [steps.SimpleStep-1572733146595]',
    '↓Set_authenticated_user [steps.SetAuthenticatedUserStep-1572733684513]',
  ]);
  assert.match(properties(yaml, 'expression').find((code) => code.includes('gid =')), /db64 = id_token_claims;/);
  for (const variable of ['code', 'keySecret', 'redirect_uri', 'client_id']) {
    assert.match(yaml, new RegExp('^↓' + variable + ' \\[variables\\.RequestableVariable-', 'm'));
  }
});

test('azure: id_token verified and bound before Graph user is trusted', () => {
  const yaml = read('loginAzureAdWithAccessToken');
  const [verify] = properties(yaml, 'expression');
  assert.match(verify, /libOAuthJwt\.verifyAzureAdIdToken\(id_token == null \? "" : String\(id_token\), access_token/);
  assertOrder(yaml, [
    '↓VerifyIdToken [steps.SimpleStep-1790600000005]',
    '↓RejectUnverifiedIdToken [steps.IfStep-1790600000006]',
    '↓Call_Transaction [steps.TransactionStep-1493473336468]',
    '↓GraphUserId [steps.SimpleSourceStep-1790600000009]',
    '↓RejectOtherUser [steps.IfStep-1790600000010]',
    '↓SaveTokenInUserSession [steps.SessionSetStep-1493626828872]',
    '↓Set_authenticated_user [steps.SetAuthenticatedUserStep-1493626951783]',
  ]);
  assert.match(yaml, /condition: '!libOAuthJwt\.graphUserMatchesIdToken\(graph_user_id, id_token_oid\)'/);
  assert.match(yaml, /^↓access_token \[variables\.RequestableVariable-1493470997723\]/m);
  assert.match(yaml, /^↓id_token \[variables\.RequestableVariable-1790600000013\]/m);
});

test('openid: introspection kept, access token verified before its claims are used', () => {
  const yaml = read('loginOpenIDWithAccessToken');
  assert.match(yaml, /sourceTransaction: lib_OAuth\.OpenID\.Introspect/);
  assert.match(yaml, /object\[active = 'true' and string-length\(normalize-space\(sub\)\) > 0\]/);
  const [verify] = properties(yaml, 'expression').filter((code) => code.includes('verifyOpenIdLogin'));
  assert.match(verify, /typeof introspection_response === "undefined" \? null : introspection_response/);
  assert.match(verify, /id_token == null \? "" : String\(id_token\)/);
  assert.match(verify, /jsonJWT = verification\.ok \? verification\.claims : \{\}/);
  assertOrder(yaml, [
    '↓Call_Transaction [steps.TransactionStep-1693495799958]',
    '↓TrustedSubject [steps.SimpleSourceStep-1789991000002]',
    '↓IntrospectionResponse [steps.JsonSourceStep-1790600000014]',
    '↓DecodeJWT [steps.SimpleStep-1693388427862]',
    '↓RejectUnverifiedAccessToken [steps.IfStep-1790600000016]',
    '↓object [steps.JsonToXmlStep-1693470137902]',
    '↓RejectMismatchedSubject [steps.IfStep-1789991000003]',
    '↓SaveTokenInUserSession [steps.SessionSetStep-1693388276590]',
    '↓authenticatedUserID [steps.SetAuthenticatedUserStep-1693473742793]',
  ]);
  assert.match(yaml, /^↓access_token \[variables\.RequestableVariable-1693388276623\]/m);
  assert.match(yaml, /^↓id_token \[variables\.RequestableVariable-1790600000019\]/m);
  assert.match(yaml, /↓IntrospectionResponse \[steps\.JsonSourceStep-1790600000014\]: \n(?:    .*\n)*?            - ↑value: \.\/document\/object\n    variableName: introspection_response/);
});

test('openid groups: read after the verification, kept in the session for the authenticated user only', () => {
  const yaml = read('loginOpenIDWithAccessToken');
  const [readGroups] = properties(yaml, 'expression').filter((code) => code.includes('openIdGroups('));
  assert.match(readGroups, /libOAuthJwt\.openIdGroups\(verification,/);
  assert.match(readGroups, /typeof introspection_response === "undefined" \? null : introspection_response/);
  const [keep] = properties(yaml, 'expression').filter((code) => code.includes('oAuthOpenIDGroups'));
  assert.match(keep, /setAttribute\("oAuthOpenIDGroups", JSON\.stringify\(\{\n\t\tuser: String\(context\.getAuthenticatedUser\(\)\)/);
  assert.match(keep, /removeAttribute\("oAuthOpenIDGroups"\)/);
  assertOrder(yaml, [
    '↓DecodeJWT [steps.SimpleStep-1693388427862]',
    '↓RejectUnverifiedAccessToken [steps.IfStep-1790600000016]',
    '↓RejectMismatchedSubject [steps.IfStep-1789991000003]',
    '↓ReadGroups [steps.SimpleStep-1799700000004]',
    '↓authenticatedUserID [steps.SetAuthenticatedUserStep-1693473742793]',
    '↓KeepGroupsInSession [steps.SimpleStep-1799700000005]',
    '↓Call_Sequence [steps.SequenceStep-1694707534295]',
  ]);
  // no request variable for the groups: they never come from the client
  assert.deepEqual([...yaml.matchAll(/^↓(\w+) \[variables\.RequestableVariable-/gm)].map((m) => m[1]), ['access_token', 'id_token']);
  // SignOut removes them with the token
  assert.match(read('SignOut'), /SessionRemoveStep-1799700000003\]: \n  key: oAuthOpenIDGroups$/);
});

test('openid scope: GetOAuthCredentials returns OpenIDScope from js/openid_scope.js', () => {
  const yaml = read('GetOAuthCredentials');
  const [scope] = properties(yaml, 'expression').filter((code) => code.includes('openid_scope'));
  assert.match(scope, /include\("js\/openid_scope\.js"\);\nvar openIdScope = libOAuthOpenIdScope\.fromSymbol\(\);/);
  assert.match(yaml, /↓OpenIDScope \[steps\.ElementStep-1799700000002\]: \n  comment: [^\n]*\n  expression: openIdScope\.encoded\n  nodeName: OpenIDScope$/);
  assertOrder(yaml, ['↓ReadOpenIDScope [steps.SimpleStep-1799700000001]', '↓OpenIDScope [steps.ElementStep-1799700000002]']);
});
