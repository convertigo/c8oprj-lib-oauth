// The callback pages getToken.html (Microsoft, OpenID: access_token and id_token in the fragment), getTokenGoogle.html and
// getTokenLinkedIn.html (authorization code in the query) give the answer of the provider to the window that opened the
// sign-in popup (Convertigo OAuth action / c8ocaf openOAuthLogin, which listens for message events).
// With postMessage(answer, '*'), any page that opened the authorize URL of a provider with a client id of an
// application and this callback got the token (silently with prompt=none once the user consented) or a code that the
// login sequences of the server exchange for a session of the user. js/oauth_callback.js posts the answer only to the
// origin of the page and to the origins of the symbol lib_oauth.callback.allowed_origins (getCallbackOrigins sequence):
// the browser drops a message whose target origin is not the origin of the receiving window.
//
// The browser tests need the playwright package and its Chromium (PLAYWRIGHT=<path of the playwright package>, else
// require('playwright')); PLAYWRIGHT_BROWSERS=chromium,firefox,webkit runs them on several browsers.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '../..');
const helperPath = path.join(root, 'js/oauth_callback.js');
const helper = fs.readFileSync(helperPath, 'utf8');
const pages = ['getToken.html', 'getTokenGoogle.html', 'getTokenLinkedIn.html'];

// The helper in a sandbox window: opener, fetch and close are recorded.
function sandbox({ origin = 'https://c8ocloud.example.net', opener = true, fetchResult, fetchError } = {}) {
  const posts = [];
  const fetches = [];
  let closed = 0;
  const window = {
    location: { origin },
    opener: opener ? { postMessage: (data, target) => posts.push({ data, target }) } : null,
    close: () => { closed++; },
    setTimeout, clearTimeout, AbortController, URL, Promise,
    fetch: async (url, init) => {
      fetches.push({ url, init });
      if (fetchError) throw fetchError;
      return { ok: true, json: async () => fetchResult };
    },
  };
  vm.createContext(window);
  vm.runInContext(helper, window, { filename: helperPath });
  return { window, posts, fetches, closed: () => closed, api: window.c8oOAuthCallback };
}

test('no page of the project posts with the target origin *, the callback pages deliver through js/oauth_callback.js', () => {
  const html = fs.readdirSync(root).filter((file) => file.endsWith('.html'));
  for (const file of html) {
    const source = fs.readFileSync(path.join(root, file), 'latin1');
    assert.doesNotMatch(source, /postMessage\s*\([^)]*['"]\*['"]\s*\)/, file);
  }
  for (const file of pages) {
    const source = fs.readFileSync(path.join(root, file), 'latin1');
    assert.match(source, /<script src="js\/oauth_callback\.js"><\/script>/, file);
    assert.match(source, /c8oOAuthCallback\.deliver\(parsedResponse\);/, file);
    assert.doesNotMatch(source, /opener\.postMessage/, file);
  }
  const code = helper.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  assert.doesNotMatch(code, /['"]\*['"]/, 'the helper never uses the target origin *');
  assert.doesNotMatch(fs.readFileSync(path.join(root, '.httpignore'), 'utf8'), /^\/?js\//m, 'js/ is served');
});

test('the getCallbackOrigins sequence answers the symbol lib_oauth.callback.allowed_origins (empty by default)', () => {
  const project = fs.readFileSync(path.join(root, 'c8oProject.yaml'), 'utf8');
  assert.match(project, /\n {2}↓getCallbackOrigins \[sequences\.GenericSequence\]: 🗏 sequences\/getCallbackOrigins\.yaml\n/);
  const sequence = fs.readFileSync(path.join(root, '_c8oProject/sequences/getCallbackOrigins.yaml'), 'utf8');
  assert.match(sequence, /\n↓origins \[steps\.XMLElementStep-\d+\]: \n {2}nodeName: origins\n {2}nodeText: \$\{lib_oauth\.callback\.allowed_origins=\}\n$/);
  assert.doesNotMatch(sequence, /accessibility/, 'public, as GetOAuthCredentials');
});

test('the allowed origins are exact http(s) origins; *, patterns, paths and other schemes are ignored', () => {
  const { api } = sandbox();
  const list = (value) => JSON.parse(JSON.stringify(api.allowedOrigins(value)));
  assert.deepEqual(list('https://forms.example.com, http://localhost:18080'), ['https://forms.example.com', 'http://localhost:18080']);
  assert.deepEqual(list(' HTTPS://Forms.Example.COM:443/ ;https://forms.example.com\nhttp://[::1]:8080'),
    ['https://forms.example.com', 'http://[::1]:8080']);
  for (const wrong of ['*', 'null', 'https://*.example.com', 'https://example.com/path', 'https://example.com?x=1',
    'https://example.com#x', 'https://user@example.com', 'ftp://example.com', 'javascript:alert(1)', 'example.com',
    'https://exa_mple.com', 'file:///etc', 'https://example.com:99999', '']) {
    assert.deepEqual(list(wrong), [], wrong);
  }
  assert.deepEqual(list(undefined), []);
  assert.deepEqual(list({}), []);
  assert.deepEqual(JSON.parse(JSON.stringify(api.targets('https://c8ocloud.example.net', '*, https://c8ocloud.example.net, https://forms.example.com'))),
    ['https://c8ocloud.example.net', 'https://forms.example.com']);
});

test('deliver posts the answer to the origin of the page and to the allowed origins only, then closes the popup', async () => {
  const answer = { access_token: 'AT', id_token: 'IT', token_type: 'Bearer', state: '12345' };
  const s = sandbox({ fetchResult: { origins: 'https://forms.example.com, *, https://*.example.com, https://evil.example/x' } });
  const targets = await s.api.deliver(answer);
  assert.deepEqual(JSON.parse(JSON.stringify(targets)), ['https://c8ocloud.example.net', 'https://forms.example.com']);
  assert.deepEqual(s.posts.map((post) => post.target), ['https://c8ocloud.example.net', 'https://forms.example.com']);
  for (const post of s.posts) assert.equal(post.data, answer, 'the answer as the page parsed it');
  assert.equal(s.closed(), 1);
  assert.equal(s.fetches.length, 1);
  assert.equal(s.fetches[0].url, '.json?__sequence=getCallbackOrigins&__removeSession=true');
  assert.equal(s.fetches[0].init.credentials, 'omit', 'the session of the user on this server is not touched');
});

test('deliver keeps the origin of the page only when the symbol is empty or cannot be read', async () => {
  for (const options of [{ fetchResult: { origins: '' } }, { fetchResult: {} }, { fetchResult: { origins: { attr: 1 } } },
    { fetchResult: { document: { origins: 'https://forms.example.com' } }, expect: ['https://c8ocloud.example.net', 'https://forms.example.com'] },
    { fetchError: new Error('network') }]) {
    const s = sandbox(options);
    await s.api.deliver({ code: 'C', state: 'c8ocsrf', access_token: 'none' });
    assert.deepEqual(s.posts.map((post) => post.target), options.expect || ['https://c8ocloud.example.net'], JSON.stringify(options));
    assert.equal(s.closed(), 1);
  }
});

test('deliver does nothing without an opener (Cordova InAppBrowser, popup opened with noopener)', async () => {
  const s = sandbox({ opener: false, fetchResult: { origins: 'https://forms.example.com' } });
  assert.deepEqual(JSON.parse(JSON.stringify(await s.api.deliver({ access_token: 'AT' }))), []);
  assert.equal(s.fetches.length, 0);
  assert.equal(s.posts.length, 0);
});

// ---------------------------------------------------------------------------------------------------------------------
// In a real browser: the callback server (as c8ocloud) serves the pages of the project, a fake provider redirects to
// them as Microsoft (fragment) or Google / LinkedIn (query) do, and the openers are an application of an allowed
// origin, a foreign page and an application of the callback server itself.

function loadPlaywright() {
  for (const name of [process.env.PLAYWRIGHT, 'playwright'].filter(Boolean)) {
    try {
      return require(name);
    } catch (e) { /* next */ }
  }
  return null;
}
const playwright = loadPlaywright();
const browserNames = (process.env.PLAYWRIGHT_BROWSERS || 'chromium').split(',').map((name) => name.trim()).filter(Boolean);
const skip = playwright ? false : 'playwright not found (PLAYWRIGHT=<path of the playwright package>)';

// The listener of c8ocaf 2.0.15 C8oRouter.openOAuthLogin (browser branch), as the Convertigo OAuth action runs it.
const opener = `<!doctype html><html><body><script>
window.received = [];
window.addEventListener('message', (event) => window.received.push({ origin: event.origin, data: event.data }));
window.openOAuthLogin = (url, redirectUri) => new Promise((resolve) => {
  url += "&redirect_uri=" + redirectUri;
  window.open(url.toString(), "cafLogin", "location=no, clearsessioncache=yes, clearcache=yes");
  window.addEventListener('message', (parsedResponse) => {
    if (parsedResponse.data["access_token"] != undefined && parsedResponse.data["access_token"] != null) {
      resolve(parsedResponse.data);
    }
  });
});
</script></body></html>`;

async function startServers() {
  const servers = { allowed: '', sequenceCalls: [], ports: {}, listeners: [] };
  const handle = (role, req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const send = (status, type, body, headers = {}) => {
      res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...headers });
      res.end(body);
    };
    if (url.pathname === '/opener.html') return send(200, 'text/html', opener);
    if (role === 'provider' && url.pathname === '/authorize') {
      const redirect = url.searchParams.get('redirect_uri');
      const answer = url.searchParams.get('mode') === 'query'
        ? '?code=CODE-' + url.searchParams.get('client_id') + '&state=' + url.searchParams.get('state')
        : '#access_token=AT-' + url.searchParams.get('client_id') + '&token_type=Bearer&expires_in=3599&scope=User.Read'
          + '&id_token=IT.x.y&state=' + url.searchParams.get('state') + '&session_state=s1';
      return send(302, 'text/plain', '', { Location: redirect + answer });
    }
    if (role === 'callback') {
      if (url.pathname === '/convertigo/scripts/jquery.min.js') return send(200, 'application/javascript', '');
      if (url.pathname === '/convertigo/projects/lib_OAuth/.json') {
        servers.sequenceCalls.push({ query: url.search, cookie: req.headers.cookie || null });
        return send(200, 'application/json', JSON.stringify({ origins: servers.allowed }));
      }
      const file = url.pathname.replace(/^\/convertigo\/projects\/lib_OAuth\//, '');
      if (file !== url.pathname && (pages.includes(file) || file === 'js/oauth_callback.js')) {
        return send(200, file.endsWith('.js') ? 'application/javascript' : 'text/html', fs.readFileSync(path.join(root, file)));
      }
    }
    return send(404, 'text/plain', 'not found');
  };
  // one server per origin (the port is part of the origin)
  for (const role of ['callback', 'allowed', 'foreign', 'provider']) {
    const server = http.createServer((req, res) => handle(role, req, res));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    servers.ports[role] = server.address().port;
    servers.listeners.push(server);
  }
  servers.origin = (role) => 'http://127.0.0.1:' + servers.ports[role];
  servers.close = () => Promise.all(servers.listeners.map((server) => new Promise((resolve) => server.close(resolve))));
  return servers;
}

// Signs in from the opener page of `from` through the callback page `page`; resolves what the opener received.
async function signIn(context, servers, { from, page, mode, state = '12345', wait = 3000 }) {
  const tab = await context.newPage();
  await tab.goto(servers.origin(from) + '/opener.html');
  if (from === 'callback') await tab.evaluate(() => { document.cookie = 'JSESSIONID=user-session; path=/'; });
  const callback = servers.origin('callback') + '/convertigo/projects/lib_OAuth/' + page;
  const authorize = servers.origin('provider') + '/authorize?client_id=c8oforms&response_type=x&scope=openid&mode=' + mode + '&state=' + state;
  const popupEvent = tab.waitForEvent('popup');
  await tab.evaluate(([url, redirect]) => { window.result = null; window.openOAuthLogin(url, redirect).then((data) => { window.result = data; }); }, [authorize, callback]);
  const popup = await popupEvent;
  const closed = new Promise((resolve) => popup.once('close', resolve));
  if (!popup.isClosed()) await Promise.race([closed, new Promise((resolve, reject) => setTimeout(() => reject(new Error('popup still open')), 15000))]);
  await tab.waitForFunction(() => window.received.length > 0, null, { timeout: wait }).catch(() => {});
  await tab.waitForTimeout(200);
  const received = await tab.evaluate(() => window.received);
  const result = await tab.evaluate(() => window.result);
  await tab.close();
  return { received, result };
}

for (const browserName of browserNames) {
  test(`${browserName}: only an opener of an allowed origin gets the answer of the provider`, { skip }, async (t) => {
    let browser;
    try {
      browser = await playwright[browserName].launch();
    } catch (e) {
      // a playwright package without its browsers (npx playwright install <browser>)
      if (process.env.PLAYWRIGHT || !/Executable doesn't exist/.test(e.message)) throw e;
      t.skip(browserName + ' not installed for this playwright package');
      return;
    }
    const servers = await startServers();
    const context = await browser.newContext();
    try {
      servers.allowed = servers.origin('allowed') + ', *, http://127.0.0.1:*';
      const flows = [
        { name: 'Microsoft', page: 'getToken.html', mode: 'fragment', state: '12345',
          expect: { access_token: 'AT-c8oforms', token_type: 'Bearer', expires_in: '3599', scope: 'User.Read', id_token: 'IT.x.y', state: '12345', session_state: 's1' } },
        { name: 'Google', page: 'getTokenGoogle.html', mode: 'query', state: 'c8ocsrf',
          expect: { code: 'CODE-c8oforms', state: 'c8ocsrf', access_token: 'none', redirect_uri: servers.origin('callback') + '/convertigo/projects/lib_OAuth/getTokenGoogle.html' } },
        { name: 'LinkedIn', page: 'getTokenLinkedIn.html', mode: 'query', state: 'c8ocsrf',
          expect: { code: 'CODE-c8oforms', state: 'c8ocsrf', access_token: 'none', redirect_uri: servers.origin('callback') + '/convertigo/projects/lib_OAuth/getTokenLinkedIn.html' } },
      ];
      for (const flow of flows) {
        await t.test(`${flow.name}: the application of an allowed origin signs in as before`, async () => {
          const r = await signIn(context, servers, { from: 'allowed', ...flow });
          assert.deepEqual(r.received, [{ origin: servers.origin('callback'), data: flow.expect }]);
          assert.deepEqual(r.result, flow.expect, 'the c8ocaf listener resolves with the answer');
        });
        await t.test(`${flow.name}: a foreign opener gets nothing`, async () => {
          const r = await signIn(context, servers, { from: 'foreign', wait: 1500, ...flow });
          assert.deepEqual(r.received, []);
          assert.equal(r.result, null);
        });
        await t.test(`${flow.name}: an application of the callback server signs in (same origin)`, async () => {
          const r = await signIn(context, servers, { from: 'callback', ...flow });
          assert.deepEqual(r.received, [{ origin: servers.origin('callback'), data: flow.expect }]);
        });
      }
      await t.test('the origins are read without the cookies of the user and the session of the call is removed', () => {
        assert.ok(servers.sequenceCalls.length >= 9);
        for (const call of servers.sequenceCalls) {
          assert.equal(call.query, '?__sequence=getCallbackOrigins&__removeSession=true');
          assert.equal(call.cookie, null);
        }
      });
      await t.test('without the symbol, only an application of the callback server gets the answer', async () => {
        servers.allowed = '';
        const allowed = await signIn(context, servers, { from: 'allowed', page: 'getToken.html', mode: 'fragment', wait: 1500 });
        assert.deepEqual(allowed.received, []);
        const same = await signIn(context, servers, { from: 'callback', page: 'getToken.html', mode: 'fragment' });
        assert.equal(same.received.length, 1);
        assert.equal(same.received[0].data.access_token, 'AT-c8oforms');
      });
    } finally {
      await browser.close();
      await servers.close();
    }
  });
}
