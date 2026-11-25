// The engine logs at INFO, the default level of the Context logger (on a server as in the Studio), the input document
// of each requestable and its answer (Generated XML); at DEBUG and TRACE the Beans logger traces the values of the step
// and requestable variables, the POST query and the HTTP request headers of each transaction.
// A variable value is masked there only when the variable has the visibility '-1' (a request header only when the
// transaction declares it as a masked __header_ variable); an answer or a header line is never masked. So the token
// variables are masked, and the calls answering or sending a token run with the MDC nolog, which the engine log filter
// denies for every logger of the thread (and of the threads of the call, which copy the MDC).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '../..');
const indent = (line) => line.length - line.trimStart().length;

function yamlFiles() {
  const files = [path.join(root, 'c8oProject.yaml')];
  for (const dir of ['connectors', 'sequences']) {
    const folder = path.join(root, '_c8oProject', dir);
    for (const name of fs.readdirSync(folder).filter((file) => file.endsWith('.yaml')).sort()) {
      files.push(path.join(folder, name));
    }
  }
  return files.map((file) => ({ file: path.relative(root, file), lines: fs.readFileSync(file, 'utf8').split('\n') }));
}

const files = yamlFiles();
const sequences = files.filter(({ file }) => file.startsWith('_c8oProject/sequences/'));
const connectors = files.filter(({ file }) => file.startsWith('_c8oProject/connectors/'));

// The nodes `↓name [kind-priority]: ` of a YAML file (at a given indent), with their lines (header, properties, children).
function nodes(lines, at) {
  const found = [];
  lines.forEach((line, start) => {
    const header = /^\s*↓(\S+) \[([\w.]+)(?:-(\d+))?\]: $/.exec(line);
    if (!header || (at !== undefined && indent(line) !== at)) {
      return;
    }
    let end = start + 1;
    while (end < lines.length && lines[end] !== '' && indent(lines[end]) > indent(line)) end++;
    const own = indent(line) + 2;
    let props = start + 1;
    while (props < end && !(indent(lines[props]) === own && lines[props].trimStart().startsWith('↓'))) props++;
    found.push({
      name: header[1], kind: header[2], id: header[3], start, end, depth: indent(line),
      lines: lines.slice(start, end),
      // own properties only (with their nested values), not the children
      props: lines.slice(start + 1, props),
      has: (property) => lines.slice(start + 1, props).some((l) => indent(l) === own && l.trim() === property),
    });
  });
  return found;
}

const masked = "visibility: '-1'";
const secretName = /^(code|__body|__header_Authorization)$|token|secret|password/i;

// The Studio writes `key: ` (with its trailing space) before nested content; a `↓name [kind]:` header without it breaks
// the load of the project, so does an unindented blank line.
test('the YAML keeps the key spaces and has no unindented blank line', () => {
  const wrong = [];
  for (const { file, lines } of files) {
    lines.forEach((line, i) => {
      if (/\]:\s*$/.test(line) && line.includes('↓') && !line.endsWith(']: ')) wrong.push(`${file}:${i + 1} header`);
      else if (line.endsWith(':') && !line.includes(': ')) wrong.push(`${file}:${i + 1} key`);
      // the last element is the end of the file (most files end with a new line, some do not)
      if (line === '' && i !== lines.length - 1) wrong.push(`${file}:${i + 1} blank line`);
    });
  }
  assert.deepEqual(wrong, []);
});

// httpInfo adds the HTTP request (headers included) to the answer of a transaction, which the engine logs.
test('the transactions are private and do not answer their HTTP request (httpInfo)', () => {
  const wrong = [];
  let count = 0;
  for (const { file, lines } of connectors) {
    for (const transaction of nodes(lines, 0).filter((node) => node.kind.startsWith('transactions.'))) {
      count++;
      if (transaction.props.some((line) => /^\s*httpInfo: true$/.test(line))) wrong.push(`${file} ${transaction.name} httpInfo`);
      if (!transaction.has('accessibility: Private')) wrong.push(`${file} ${transaction.name} not private`);
    }
  }
  assert.ok(count >= 13, `${count} transactions`);
  assert.deepEqual(wrong, []);
});

test('the variables carrying a token or a secret are masked in the logs', () => {
  const wrong = [];
  let count = 0;
  for (const { file, lines } of files) {
    for (const variable of nodes(lines).filter((node) => node.kind.startsWith('variables.') && secretName.test(node.name))) {
      // the variables of a test case only feed the sequence variables, which are masked
      if (variable.kind === 'variables.TestCaseVariable') continue;
      count++;
      if (!variable.has(masked)) wrong.push(`${file}:${variable.start + 1} ${variable.name} [${variable.kind}]`);
    }
  }
  assert.ok(count >= 36, `${count} variables`);
  assert.deepEqual(wrong, []);
});

// Without a declared __header_Authorization the engine logs the header in clear in the input document of the transaction.
test('a call sending a Bearer goes to a transaction declaring the masked Authorization header', () => {
  const transactions = new Map();
  for (const { file, lines } of connectors) {
    const connector = path.basename(file, '.yaml');
    for (const transaction of nodes(lines, 0)) {
      const header = nodes(transaction.lines, 2).find((node) => node.name === '__header_Authorization');
      transactions.set(`lib_OAuth.${connector}.${transaction.name}`, Boolean(header && header.has(masked)));
    }
  }
  const wrong = [];
  let count = 0;
  for (const { file, lines } of sequences) {
    for (const step of nodes(lines).filter((node) => node.kind === 'steps.TransactionStep')) {
      if (!nodes(step.lines, step.depth + 2).some((node) => node.name === '__header_Authorization')) continue;
      count++;
      const target = step.props.map((line) => /^\s*sourceTransaction: (\S+)$/.exec(line)).find(Boolean)[1];
      if (!transactions.get(target)) wrong.push(`${file}:${step.start + 1} ${step.name} -> ${target}`);
    }
  }
  assert.equal(count, 7);
  assert.deepEqual(wrong, []);
});

// The answer of these requestables holds a token, the request of the others sends one (Authorization header or body).
const tokenAnswers = /^\s*source(Transaction|Sequence): lib_OAuth\.(GoogleOAuth\.GetToken|LinkedInOAuth\.Authorize|GitHubOAuth\.GetToken|checkAccess\w*)$/;
const tokenRequests = /^\s*sourceTransaction: lib_OAuth\.OpenID\.Introspect$/;
const put = 'expression: org.apache.log4j.MDC.put("nolog", true);';
const remove = 'expression: org.apache.log4j.MDC.remove("nolog");';

function tokenCalls(lines) {
  return nodes(lines).filter((step) => (step.kind === 'steps.TransactionStep' || step.kind === 'steps.SequenceStep')
    && (step.props.some((line) => tokenAnswers.test(line) || tokenRequests.test(line))
      || nodes(step.lines, step.depth + 2).some((node) => node.name === '__header_Authorization')));
}

test('the calls answering or sending a token run with the logs off', () => {
  const wrong = [];
  let count = 0;
  for (const { file, lines } of sequences) {
    for (const call of tokenCalls(lines)) {
      count++;
      const siblings = nodes(lines, call.depth);
      const at = siblings.findIndex((node) => node.start === call.start);
      const before = siblings[at - 1];
      const after = siblings[at + 1];
      const ok = before && before.end === call.start && before.kind === 'steps.SimpleStep' && before.has(put)
        && after && after.start === call.end && after.kind === 'steps.SimpleStep' && after.has(remove);
      if (!ok) wrong.push(`${file}:${call.start + 1} ${call.name}`);
    }
  }
  assert.equal(count, 12);
  assert.deepEqual(wrong, []);
});

// A nolog left set would silence the rest of the sequence, its errors included.
test('each nolog is removed right after its call', () => {
  const wrong = [];
  for (const { file, lines } of sequences) {
    const all = nodes(lines);
    const puts = all.filter((node) => node.kind === 'steps.SimpleStep' && node.has(put));
    const removes = all.filter((node) => node.kind === 'steps.SimpleStep' && node.has(remove));
    if (puts.length !== removes.length) wrong.push(`${file} ${puts.length} put / ${removes.length} remove`);
    for (const step of puts) {
      const siblings = nodes(lines, step.depth);
      const at = siblings.findIndex((node) => node.start === step.start);
      const call = siblings[at + 1];
      const after = siblings[at + 2];
      if (!call || !['steps.TransactionStep', 'steps.SequenceStep'].includes(call.kind)
        || !after || after.kind !== 'steps.SimpleStep' || !after.has(remove)) {
        wrong.push(`${file}:${step.start + 1} ${step.name}`);
      }
    }
  }
  assert.deepEqual(wrong, []);
});

// The scripts of the sequences only log the reason of a refusal, never a variable holding a token.
test('the step scripts do not log a token', () => {
  const tokenVariables = /\b(access_token|id_token|code|keySecret|client_secret|bearer|token|introspection_response|id_token_claims|jsonJWT|db64)\b/;
  const wrong = [];
  for (const { file, lines } of sequences) {
    lines.forEach((line, i) => {
      if (!/\blog\.(trace|debug|info|warn|error)\(/.test(line)) return;
      const code = line.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'(?:[^'\\]|\\.)*'/g, "''");
      if (tokenVariables.test(code)) wrong.push(`${file}:${i + 1}`);
    });
  }
  assert.deepEqual(wrong, []);
  assert.doesNotMatch(fs.readFileSync(path.join(root, 'js/jwt_verify.js'), 'utf8'), /\blog\.(trace|debug|info|warn|error)\(/);
});

// A top-level login answer is logged by the engine in the HTTP thread, which a step cannot silence: the steps writing
// to the output never copy a token from the answer of a token endpoint.
test('no output step copies a token from the answer of a token endpoint', () => {
  const tokenEndpoints = /^\s*sourceTransaction: lib_OAuth\.(GoogleOAuth\.GetToken|LinkedInOAuth\.Authorize|GitHubOAuth\.GetToken)$/;
  const silent = ['steps.IfExistThenElseStep', 'steps.IfExistStep', 'steps.SimpleSourceStep', 'steps.JsonSourceStep',
    'steps.SessionSetStep', 'steps.TransactionStep', 'steps.SequenceStep'];
  const noToken = /\[not\(access_token\) and not\(id_token\) and not\(refresh_token\)\]$/;
  const wrong = [];
  let count = 0;
  for (const { file, lines } of sequences) {
    const all = nodes(lines);
    const ids = all.filter((step) => step.props.some((line) => tokenEndpoints.test(line))).map((step) => step.id);
    for (const step of all) {
      step.props.forEach((line, i) => {
        const source = /^\s*- ↑value: (\d+)$/.exec(line);
        if (!source || !ids.includes(source[1])) return;
        count++;
        const xpath = step.props.slice(i + 1).map((next) => /^\s*- ↑value: (.*)$/.exec(next)).find(Boolean)[1];
        if (silent.includes(step.kind) || step.has('output: false') || noToken.test(xpath)) return;
        wrong.push(`${file}:${step.start + 1} ${step.name} ${xpath}`);
      });
    }
  }
  assert.equal(count, 6);
  assert.deepEqual(wrong, []);
});
