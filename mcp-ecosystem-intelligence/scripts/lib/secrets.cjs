'use strict';
/**
 * Secrets written in plain text into the MCP host configs this tool already
 * reads.
 *
 * Everything else here asks whether the *server* is safe to run. The config
 * that launches it is the other half: `claude mcp add -e GITHUB_TOKEN=ghp_…`
 * writes the token into `~/.claude.json`, a README says "paste your key into
 * `env`", and `.mcp.json` is a file teams commit. The token then sits in a
 * dotfile, a backup, a screen share and — for a committed `.mcp.json` — in git
 * history for everyone with the repo.
 *
 * The one rule this module is built around: **the value never leaves it.** A
 * finding carries the type, the file, the path to the key, the length and a
 * masked prefix of at most four characters — for a known format, the part of
 * the prefix that is public anyway (`ghp_`, `AKIA`); for a heuristic match,
 * nothing, because there every character is secret. A scanner that prints the
 * secret it found has just made a second copy of it, in a CI log.
 *
 * Offline, deterministic, no dependencies. The one subprocess is
 * `git ls-files`, to say whether the file is tracked; when git is missing that
 * answer is `null`, not `false`.
 *
 * API:
 *   scanString(value, ctx)                 -> [{ rule, label, secret, prefix }]  (internal: carries the value)
 *   scanServer(spec, basePath, ctx)        -> [finding]                            (no value)
 *   scanDocument(doc, loc)                 -> [finding]
 *   scanHostConfigs({ cwd, home, platform, paths, git }) -> { files, findings, unreadable }
 *   parseCodexTomlServers(text)            -> { mcp_servers: { name: { … } } }
 *   recommendation(host, scope)            -> string
 *   fixSuggestion(finding)                 -> { lines: [...] } | { manual: string }
 *   maskValue(value, publicPrefixLen)      -> string
 *   redact(string)                         -> string with every secret masked
 *   toFindings(scan, { cwd })              -> { findings, subjects, details }  (lib/finding.cjs findings)
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { spawnSync } = require('child_process');
const { hostConfigPaths } = require('./installed.cjs');
const { finding, subject } = require('./finding.cjs');

// ── known formats ──────────────────────────────────────────────────────────
//
// `prefix` is how many leading characters of a match are the format's public
// marker, and therefore safe to show (capped at 4 below). Order matters where
// formats overlap: `sk-ant-` is checked before the generic `sk-`.

const KNOWN = [
  { rule: 'private-key',       label: 'PEM private key',              prefix: 4,
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|$)/g },
  { rule: 'github-token',      label: 'GitHub token',                 prefix: 4,
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g },
  { rule: 'github-pat',        label: 'GitHub fine-grained token',    prefix: 4,
    re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { rule: 'gitlab-token',      label: 'GitLab token',                 prefix: 4,
    re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
  { rule: 'aws-access-key',    label: 'AWS access key id',            prefix: 4,
    re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { rule: 'slack-token',       label: 'Slack token',                  prefix: 4,
    re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { rule: 'anthropic-key',     label: 'Anthropic API key',            prefix: 4,
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { rule: 'openai-key',        label: 'OpenAI-style API key (sk-)',   prefix: 3,
    re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g },
  { rule: 'stripe-live-key',   label: 'Stripe live key',              prefix: 4,
    re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/g },
  { rule: 'google-api-key',    label: 'Google API key',               prefix: 4,
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { rule: 'jwt',               label: 'JSON Web Token',               prefix: 3,
    re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
];

// Database URLs with a password in the userinfo. Other schemes with a
// password are `url-credentials`; the split is only for the label.
const DB_SCHEMES = /^(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?)$/i;
const URL_RE = /\b([a-z][a-z0-9+.-]*):\/\/([^\s/?#@"']+)@([^\s"']+)/gi;
const QUERY_RE = /[?&]([A-Za-z0-9_.-]+)=([^&#\s"']+)/g;
const BEARER_RE = /\bBearer\s+([A-Za-z0-9\-._~+/]{16,}=*)/g;

// A reference to be substituted at launch, in any host's syntax. A value that
// contains one is not a literal, and the heuristic leaves it alone.
const REFERENCE_RE = /\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]*\}\}|%[A-Za-z_][A-Za-z0-9_]*%/;

// Names that suggest the value is a credential. `_ID`/`_PATH`/… suffixes are
// the name of something *about* a key, not the key.
const SECRET_NAME_RE = /(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|KEY|AUTHORIZATION|COOKIE)/i;
const NOT_SECRET_SUFFIX_RE = /(_|-)(PATH|FILE|DIR|ID|NAME|URL|URI|HOST|PORT|TYPE|ENV|VAR|REGION|USER|USERNAME)$/i;
const PASSWORD_NAME_RE = /(PASSWORD|PASSWD|PASSPHRASE|PWD)/i;

const PLACEHOLDER_RE = /^(?:<[^>]*>|\[[^\]]*\]|x{3,}|\*{3,}|\.{3,}|your[-_ ].*|.*[-_]here|changeme|change[-_]me|replace[-_ ]?me|todo|tbd|redacted|none|null|undefined|true|false|example.*|dummy.*|placeholder.*|test|secret|password|token)$/i;

function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

function isSecretName(name) {
  if (!name) return false;
  const n = String(name).replace(/^-+/, '');
  return SECRET_NAME_RE.test(n) && !NOT_SECRET_SUFFIX_RE.test(n);
}

/**
 * Would this literal be a credential if its name says it is one? Length and
 * entropy keep `API_KEY_HEADER=x-api-key` and `TOKEN_TTL=3600` out; passwords
 * get a lower bar because people choose them.
 */
function looksLikeSecretValue(value, name) {
  const v = String(value).trim();
  if (!v || REFERENCE_RE.test(v) || PLACEHOLDER_RE.test(v)) return false;
  if (/^([~.]?\/|[A-Za-z]:\\|file:)/.test(v)) return false;          // a path to a key, not a key
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return false;               // URLs are checked on their own
  if (/^\d+$/.test(v)) return false;
  const pw = PASSWORD_NAME_RE.test(String(name || ''));
  const minLen = pw ? 8 : 16;
  const minH   = pw ? 2.5 : 3.0;
  if (v.length < minLen) return false;
  if (/\s/.test(v) && !pw) return false;                             // prose, not a token
  return entropy(v) >= minH;
}

/**
 * Every secret-shaped thing inside one string. Returns the matched secret
 * itself — this is the only function that does, and nothing it returns is
 * printed; `scanServer` turns it into a finding and drops the value.
 *
 * @param ctx.name  the key or flag this string belongs to, for the heuristic
 */
function scanString(value, { name = null } = {}) {
  if (typeof value !== 'string' || !value) return [];
  const hits = [];
  const taken = [];              // [start, end) spans already attributed
  const overlaps = (s, e) => taken.some(([a, b]) => s < b && e > a);
  const add = (hit, start, end) => {
    if (overlaps(start, end)) return;
    taken.push([start, end]);
    hits.push(hit);
  };

  for (const k of KNOWN) {
    k.re.lastIndex = 0;
    let m;
    while ((m = k.re.exec(value))) {
      add({ rule: k.rule, label: k.label, secret: m[0], prefix: k.prefix, confidence: 'format' }, m.index, m.index + m[0].length);
    }
  }

  URL_RE.lastIndex = 0;
  let m;
  while ((m = URL_RE.exec(value))) {
    const [, scheme, userinfo] = m;
    const colon = userinfo.indexOf(':');
    if (colon < 0) continue;
    const pass = userinfo.slice(colon + 1);
    if (!pass || REFERENCE_RE.test(pass) || PLACEHOLDER_RE.test(pass)) continue;
    const start = m.index + scheme.length + 3 + colon + 1;
    const db = DB_SCHEMES.test(scheme);
    add({
      rule: db ? 'connection-string' : 'url-credentials',
      label: db ? `${scheme.toLowerCase()} connection string with a password` : 'password in URL userinfo',
      secret: pass, prefix: 0, confidence: 'format',
    }, start, start + pass.length);
  }

  QUERY_RE.lastIndex = 0;
  while ((m = QUERY_RE.exec(value))) {
    const [, key, v] = m;
    if (!(isSecretName(key) || /^(sig|signature|auth|apikey|access_token|code)$/i.test(key))) continue;
    if (v.length < 8 || REFERENCE_RE.test(decodeSafe(v)) || PLACEHOLDER_RE.test(v)) continue;
    const start = m.index + m[0].length - v.length;
    add({ rule: 'url-query-token', label: `credential in URL query (${key})`, secret: v, prefix: 0, confidence: 'format', name: key }, start, start + v.length);
  }

  BEARER_RE.lastIndex = 0;
  while ((m = BEARER_RE.exec(value))) {
    const tok = m[1];
    const start = m.index + m[0].length - tok.length;
    add({ rule: 'bearer-token', label: 'Bearer token', secret: tok, prefix: 0, confidence: 'format' }, start, start + tok.length);
  }

  // The heuristic only when nothing more specific matched: a named, literal,
  // high-entropy value. `NAME=value` inside a string (`docker -e`) names itself.
  if (!hits.length) {
    let n = name;
    let v = value;
    const assign = value.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/s);
    if (assign && isSecretName(assign[1])) { n = assign[1]; v = assign[2]; }
    else {
      const flag = value.match(/^(--?[A-Za-z][A-Za-z0-9_-]*)=(.+)$/s);
      if (flag && isSecretName(flag[1])) { n = flag[1]; v = flag[2]; }
    }
    // `Authorization: Basic …` and friends: the scheme word is not the secret.
    if (/^(authorization|proxy-authorization)$/i.test(String(n || '').replace(/^.*[.:]/, ''))) {
      v = v.replace(/^[A-Za-z]+\s+/, '');
    }
    const header = value.match(/^([A-Za-z][A-Za-z0-9-]*):\s*(?:[A-Za-z]+\s+)?(.+)$/s);
    if (!isSecretName(n) && header && isSecretName(header[1])) { n = header[1]; v = header[2]; }
    if (isSecretName(n) && looksLikeSecretValue(v, n)) {
      hits.push({ rule: 'named-secret', label: `literal value for a credential-named key (${String(n).replace(/^-+/, '')})`,
        secret: v.trim(), prefix: 0, confidence: 'heuristic', name: String(n).replace(/^-+/, '') });
    }
  }
  return hits;
}

function decodeSafe(s) { try { return decodeURIComponent(s); } catch { return s; } }

/**
 * At most four characters, and only those the format makes public. For a
 * heuristic match there is no public part, so nothing of the value is shown.
 */
function maskValue(value, publicPrefixLen = 0) {
  const n = Math.max(0, Math.min(4, publicPrefixLen, String(value).length - 1));
  return `${String(value).slice(0, n)}…`;
}

/**
 * The string with every secret in it replaced by its mask. For output that
 * has to show a launch command (`status` prints `launches`): an `args` entry
 * can be `postgres://u:<password>@…` or `--header "Authorization: Bearer …"`.
 */
function redact(value) {
  if (typeof value !== 'string') return value;
  let out = value;
  // The whole string for the formats, each word for `NAME=value`: a joined
  // command line is one string, and the heuristic reads one value at a time.
  // A word right after a credential-named flag is filed under that flag
  // (`--api-key <value>`), the same pairing `leaves()` makes for `args`: the
  // joined command has lost the array, not the order.
  const words = value.split(/\s+/);
  const hits = [...scanString(value), ...words.flatMap((w, i) => {
    const prev = i > 0 && /^--?[A-Za-z]/.test(words[i - 1]) && !words[i - 1].includes('=') ? words[i - 1] : null;
    return scanString(w, { name: prev });
  })];
  for (const hit of hits) out = out.split(hit.secret).join(maskValue(hit.secret, hit.prefix));
  return out;
}

// ── walking a config ───────────────────────────────────────────────────────

function keyPath(base, key) {
  if (typeof key === 'number') return `${base}[${key}]`;
  return /^[A-Za-z_][A-Za-z0-9_-]*$/.test(key) ? `${base}.${key}` : `${base}[${JSON.stringify(key)}]`;
}

/**
 * Every string leaf of one server's spec, with the name that governs it: the
 * object key, or for an `args` entry the flag right before it
 * (`--api-key`, `sk-…`).
 */
function* leaves(node, p, name, field) {
  if (typeof node === 'string') { yield { value: node, path: p, name, field }; return; }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const prev = i > 0 && typeof node[i - 1] === 'string' && /^--?[A-Za-z]/.test(node[i - 1]) && !node[i - 1].includes('=')
        ? node[i - 1] : null;
      // `-e NAME=value` / `--header "X-Api-Key: …"` carry their own name.
      yield* leaves(node[i], keyPath(p, i), prev && !/^-(e|-env|H|-header)$/.test(prev) ? prev : name, field);
    }
    return;
  }
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) yield* leaves(v, keyPath(p, k), k, field || k);
  }
}

/**
 * Findings for one server entry. No finding carries the value — only its
 * length and `maskValue`. `origin` is { host, scope, file, server }.
 */
function scanServer(spec, basePath, origin = {}) {
  const out = [];
  if (!spec || typeof spec !== 'object') return out;
  for (const leaf of leaves(spec, basePath, null, null)) {
    // Names that *hold* env var names are references by construction.
    if (/^(env_vars|env_http_headers|bearer_token_env_var)$/.test(leaf.field || '')) continue;
    for (const hit of scanString(leaf.value, { name: leaf.name })) {
      out.push({
        category: 'secret',
        rule: hit.rule,
        type: hit.label,
        confidence: hit.confidence,
        host: origin.host || null,
        scope: origin.scope || null,
        file: origin.file || null,
        server: origin.server || null,
        path: leaf.path,
        field: leaf.field,
        // The name the value is filed under: the env key, header, flag or
        // query parameter — whichever named it.
        key: hit.name || (leaf.name ? String(leaf.name).replace(/^-+/, '') : null),
        length: hit.secret.length,
        masked: maskValue(hit.secret, hit.prefix),
        // Internal, stripped before anything is returned from this module.
        [SECRET]: hit.secret,
      });
    }
  }
  return out;
}

// Symbols, so `JSON.stringify` and `Object.keys` cannot see them even if a
// caller forgets to strip. Stripped anyway.
const SECRET = Symbol('secret');

/**
 * The server maps inside one parsed config. Only server maps: `~/.claude.json`
 * also holds Claude Code's own OAuth state, and a scanner that walked the
 * whole file would be reporting on (and one bug away from printing) that.
 */
function serverMaps(doc, host) {
  const maps = [];
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return maps;
  if (host === 'codex') {
    if (doc.mcp_servers && typeof doc.mcp_servers === 'object') maps.push({ base: 'mcp_servers', servers: doc.mcp_servers });
    return maps;
  }
  const key = doc.mcpServers !== undefined ? 'mcpServers' : (doc.servers !== undefined ? 'servers' : null);
  if (key && doc[key] && typeof doc[key] === 'object' && !Array.isArray(doc[key])) maps.push({ base: key, servers: doc[key] });
  // Claude Code's local scope (`claude mcp add`, the default) lives here,
  // per project — the place `-e TOKEN=…` most often ends up.
  if (host === 'claude-code' && doc.projects && typeof doc.projects === 'object') {
    for (const [proj, cfg] of Object.entries(doc.projects)) {
      if (cfg && typeof cfg.mcpServers === 'object' && cfg.mcpServers && !Array.isArray(cfg.mcpServers)) {
        maps.push({ base: `projects[${JSON.stringify(proj)}].mcpServers`, servers: cfg.mcpServers, scope: 'local' });
      }
    }
  }
  return maps;
}

function scanDocument(doc, loc) {
  const findings = [];
  for (const map of serverMaps(doc, loc.host)) {
    for (const [name, spec] of Object.entries(map.servers)) {
      findings.push(...scanServer(spec, keyPath(map.base, name), {
        host: loc.host, scope: map.scope || loc.scope, file: loc.path, server: name,
      }));
    }
  }
  return findings;
}

// ── Codex TOML ─────────────────────────────────────────────────────────────

/**
 * Enough TOML to read `[mcp_servers.*]` and its sub-tables (`env`,
 * `http_headers`): basic and literal strings, arrays (also multi-line),
 * inline tables, dotted keys. Everything outside `mcp_servers` is skipped
 * unread. Narrow for the same reason `installed.cjs` is narrow — but this one
 * has to see `env`, which that parser deliberately drops.
 */
function parseCodexTomlServers(text) {
  const root = { mcp_servers: {} };
  // The object values are assigned into, or null = skip. Before the first
  // header it is the TOML root, where only `mcp_servers.…` dotted keys count
  // (`mcp_servers.gh.env.GITHUB_TOKEN = "…"`, `mcp_servers.gh = { … }`).
  let table = root;
  let atRoot = true;
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    const header = line.match(/^\[\s*([^\[\]]+?)\s*\]\s*(#.*)?$/);
    if (header) {
      const keys = splitKey(header[1]);
      atRoot = false;
      if (keys[0] !== 'mcp_servers') { table = null; continue; }
      table = root;
      for (const k of keys) table = (table[k] && typeof table[k] === 'object') ? table[k] : (table[k] = {});
      continue;
    }
    if (/^\[\[/.test(line)) { table = null; atRoot = false; continue; }
    if (!table) continue;
    const eq = findAssign(line);
    if (eq < 0) continue;
    const keys = splitKey(line.slice(0, eq));
    let rest = line.slice(eq + 1).trim();
    // Multi-line arrays / inline tables: keep reading until brackets balance.
    const at = i + 1;
    while (!balanced(rest) && i + 1 < lines.length) rest += '\n' + lines[++i];
    if (atRoot && keys[0] !== 'mcp_servers') continue;
    // A value this parser cannot read inside a server table is an unreadable
    // config, not an empty one: skipping it would report "clean" about a
    // value nobody looked at (scanHostConfigs turns the throw into exit 2).
    let value;
    try { value = parseValue(rest, { i: 0 }); } catch (e) { throw new Error(`line ${at}: ${e.message}`); }
    let t = table;
    for (const k of keys.slice(0, -1)) t = (t[k] && typeof t[k] === 'object') ? t[k] : (t[k] = {});
    t[keys[keys.length - 1]] = value;
  }
  return root;
}

function splitKey(s) {
  const out = [];
  const re = /\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*(?:\.|$)/g;
  let m;
  while ((m = re.exec(s)) && m[0]) {
    const k = m[1];
    out.push(k.startsWith('"') ? JSON.parse(k) : k.replace(/^'(.*)'$/, '$1'));
  }
  return out;
}

function findAssign(line) {
  let q = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '\\' && q === '"') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '=') return i;
  }
  return -1;
}

function balanced(s) {
  let depth = 0; let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\' && q === '"') i++; else if (c === q) q = null; continue; }
    if (c === '#') { const nl = s.indexOf('\n', i); if (nl < 0) break; i = nl; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') depth--;
  }
  return depth <= 0 && !q;
}

function parseValue(s, pos) {
  skipWs(s, pos);
  const c = s[pos.i];
  if (c === '"') {
    if (s.startsWith('"""', pos.i)) {
      const end = s.indexOf('"""', pos.i + 3);
      if (end < 0) throw new Error('unterminated string');
      const v = s.slice(pos.i + 3, end).replace(/^\n/, '');
      pos.i = end + 3; return v;
    }
    let j = pos.i + 1; let v = '';
    while (j < s.length && s[j] !== '"') {
      if (s[j] === '\\') { const e = s[j + 1]; v += ({ n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\' })[e] ?? e; j += 2; }
      else v += s[j++];
    }
    if (j >= s.length) throw new Error('unterminated string');
    pos.i = j + 1; return v;
  }
  if (c === "'") {
    const q = s.startsWith("'''", pos.i) ? "'''" : "'";
    const end = s.indexOf(q, pos.i + q.length);
    if (end < 0) throw new Error('unterminated string');
    let v = s.slice(pos.i + q.length, end);
    if (q.length === 3) v = v.replace(/^\n/, '');
    pos.i = end + q.length; return v;
  }
  if (c === '[') {
    pos.i++; const arr = [];
    for (;;) {
      skipWs(s, pos);
      if (s[pos.i] === ']') { pos.i++; return arr; }
      if (pos.i >= s.length) throw new Error('unterminated array');
      arr.push(parseValue(s, pos));
      skipWs(s, pos);
      if (s[pos.i] === ',') pos.i++;
      else if (s[pos.i] === ']') { pos.i++; return arr; }
      else throw new Error('bad array');
    }
  }
  if (c === '{') {
    pos.i++; const obj = {};
    for (;;) {
      skipWs(s, pos);
      if (s[pos.i] === '}') { pos.i++; return obj; }
      if (pos.i >= s.length) throw new Error('unterminated inline table');
      const rest = s.slice(pos.i);
      const eq = findAssign(rest);
      if (eq < 0) throw new Error('bad inline table');
      const keys = splitKey(rest.slice(0, eq));
      pos.i += eq + 1;
      let t = obj;
      for (const k of keys.slice(0, -1)) t = t[k] || (t[k] = {});
      t[keys[keys.length - 1]] = parseValue(s, pos);
      skipWs(s, pos);
      if (s[pos.i] === ',') pos.i++;
    }
  }
  const m = s.slice(pos.i).match(/^[^,\]}\s#]+/);
  if (!m) throw new Error('bad value');
  pos.i += m[0].length;
  return m[0];               // numbers / booleans / dates: kept as text, never secrets
}

function skipWs(s, pos) {
  for (;;) {
    while (pos.i < s.length && /\s/.test(s[pos.i])) pos.i++;
    if (s[pos.i] === '#') { const nl = s.indexOf('\n', pos.i); pos.i = nl < 0 ? s.length : nl; continue; }
    return;
  }
}

// ── git ────────────────────────────────────────────────────────────────────

/**
 * true: git tracks this file, so the secret is in history. false: git
 * answered, and it is not tracked (or not in a repository). null: git could
 * not be asked — not the same as false.
 */
function gitTracked(file) {
  let r;
  try {
    r = spawnSync('git', ['ls-files', '--error-unmatch', '--', path.basename(file)], {
      cwd: path.dirname(file), encoding: 'utf8', timeout: 5000,
      env: { ...process.env, GIT_OPTIONAL_LOCKS: '0' },
    });
  } catch { return null; }
  if (r.error) return null;
  if (r.status === 0) return true;
  if (r.status === 1) return false;
  if (/not a git repository/i.test(r.stderr || '')) return false;
  return null;
}

// ── recommendations ────────────────────────────────────────────────────────
//
// What each host documents for keeping a value out of the file. Where a host
// documents nothing, this says so rather than inventing a syntax that would
// then be pasted in and silently passed through as a literal string.
// Checked against each host's docs on 2026-09-30.

const RECOMMEND = {
  'claude-code:project': 'Claude Code expands `${VAR}` (and `${VAR:-default}`) in .mcp.json — in command, args, env, url and headers. Replace the literal with `${NAME}` and set NAME in the environment that starts Claude Code.',
  'claude-code:user': 'Claude Code documents `${VAR}` expansion for .mcp.json only, not for ~/.claude.json. Either move this server to a project .mcp.json and use `${NAME}` there, or check whether your Claude Code version expands it here before relying on it.',
  'claude-code:local': 'Claude Code documents `${VAR}` expansion for .mcp.json only, not for the per-project entries in ~/.claude.json (`claude mcp add` local scope). Either move this server to .mcp.json with `${NAME}`, or check whether your Claude Code version expands it here before relying on it.',
  'claude-desktop:user': 'Claude Desktop documents no environment-variable substitution in claude_desktop_config.json that we could find. Options: launch through a wrapper script that reads the secret from the OS keychain, or use a Desktop Extension whose user_config marks the field sensitive. Not verified further — check the current Claude Desktop docs.',
  'cursor:project': 'Cursor interpolates `${env:NAME}` in command, args, env, url and headers of mcp.json; stdio servers can also use `envFile`. Replace the literal with `${env:NAME}`.',
  'cursor:user': 'Cursor interpolates `${env:NAME}` in command, args, env, url and headers of mcp.json; stdio servers can also use `envFile`. Replace the literal with `${env:NAME}`.',
  'vscode:project': 'VS Code: declare an entry in the top-level `inputs` array (`"type": "promptString", "password": true`) and reference it as `${input:<id>}` — VS Code prompts once and stores it securely. `envFile` is the alternative for stdio servers. `${env:VAR}` is not documented for mcp.json.',
  'codex:user': 'Codex does not document `${VAR}` expansion in config.toml. Forward the variable from your shell with `env_vars = ["NAME"]`, use `bearer_token_env_var = "NAME"` for an HTTP bearer token, or `env_http_headers = { "Header" = "NAME" }` for other headers.',
};

function recommendation(host, scope) {
  return RECOMMEND[`${host}:${scope}`] || 'Move the value to the environment and reference it by name, in whatever syntax this host documents.';
}

/** An env var name for a finding: the key if it is one, else from the rule. */
function suggestedName(f) {
  const envName = (k) => String(k).replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '').toUpperCase();
  // A top-level field name (`args`, `url`) is where the value sits, not what it is.
  const named = f.key && f.key !== f.field ? envName(f.key) : null;
  if (named && f.field === 'env') return named;
  const byRule = {
    'github-token': 'GITHUB_TOKEN', 'github-pat': 'GITHUB_TOKEN', 'gitlab-token': 'GITLAB_TOKEN',
    'aws-access-key': 'AWS_ACCESS_KEY_ID', 'slack-token': 'SLACK_TOKEN', 'anthropic-key': 'ANTHROPIC_API_KEY',
    'openai-key': 'OPENAI_API_KEY', 'stripe-live-key': 'STRIPE_SECRET_KEY', 'google-api-key': 'GOOGLE_API_KEY',
    'connection-string': 'DATABASE_PASSWORD', 'url-credentials': 'URL_PASSWORD', 'private-key': 'PRIVATE_KEY',
  };
  if (byRule[f.rule]) return byRule[f.rule];
  const k = named && named !== 'AUTHORIZATION' ? named : `${envName(f.server || '')}_TOKEN`.replace(/^_/, '');
  return /^[0-9]/.test(k) ? `_${k}` : (k || 'SECRET');
}

function referenceFor(host, scope, name) {
  if (host === 'claude-code' && scope === 'project') return '${' + name + '}';
  if (host === 'cursor') return '${env:' + name + '}';
  if (host === 'vscode') return '${input:' + name.toLowerCase().replace(/_/g, '-') + '}';
  return null;
}

/**
 * A suggested edit, printed and never applied. The "-" line shows the leaf
 * with every secret in it masked; the "+" line puts the reference in its
 * place. Hosts with no documented substitution get the recommendation instead
 * of an edit nobody can make work.
 *
 * `leafMasked` / `leafFixed` are built by the caller from the leaf value, so
 * this module stays the only place the value exists.
 */
function fixSuggestion(f) {
  const name = suggestedName(f);
  if (f.host === 'codex') {
    if (f.field === 'env' && f.key) {
      return { lines: [
        `- ${f.path} = "${f.masked}"`,
        `+ (remove it, and in [${f.path.split('.env')[0]}]:) env_vars = ["${f.key}"]`,
      ] };
    }
    if (f.field === 'http_headers' && f.key) {
      return { lines: [
        `- ${f.path} = "${f.masked}"`,
        `+ (remove it, and in [${f.path.split('.http_headers')[0]}]:) env_http_headers = { ${JSON.stringify(f.key)} = "${name}" }`,
      ], env: name };
    }
    return { manual: recommendation(f.host, f.scope) };
  }
  const ref = referenceFor(f.host, f.scope, name);
  if (!ref) return { manual: recommendation(f.host, f.scope) };
  const lines = [`- ${f.path}: ${JSON.stringify(f.leaf_masked)}`, `+ ${f.path}: ${JSON.stringify(f.leaf_fixed(ref))}`];
  if (f.host === 'vscode') {
    const id = ref.slice('${input:'.length, -1);
    lines.push(`+ inputs[]: ${JSON.stringify({ type: 'promptString', id, description: name, password: true })}`);
  }
  return { lines, env: name };
}

// ── the whole scan ─────────────────────────────────────────────────────────

function lineOf(raw, secret) {
  for (const needle of [secret, JSON.stringify(secret).slice(1, -1)]) {
    const at = raw.indexOf(needle);
    if (at >= 0) return raw.slice(0, at).split('\n').length;
  }
  return null;
}

/**
 * Read every host config, return findings that carry no secret value.
 *
 * @param git  false skips the `git ls-files` check (tracked: null)
 */
function scanHostConfigs({ cwd = process.cwd(), home = os.homedir(), platform = process.platform, paths = null, git = true } = {}) {
  const locations = paths || hostConfigPaths({ cwd, home, platform });
  const files = [];
  const unreadable = [];
  const findings = [];
  const trackedCache = new Map();

  for (const loc of locations) {
    let raw;
    try { raw = fs.readFileSync(loc.path, 'utf8'); }
    catch (e) {
      if (e.code !== 'ENOENT') unreadable.push({ ...loc, error: `${e.code || 'read failed'}: ${e.message}` });
      continue;
    }
    let doc;
    try { doc = loc.path.endsWith('.toml') ? parseCodexTomlServers(raw) : JSON.parse(raw); }
    catch (e) { unreadable.push({ ...loc, error: `parse failed: ${parseErrorWithoutContent(e)}` }); continue; }
    files.push({ host: loc.host, scope: loc.scope, path: loc.path });

    const found = scanDocument(doc, loc);
    if (!found.length) continue;
    if (!trackedCache.has(loc.path)) trackedCache.set(loc.path, git ? gitTracked(loc.path) : null);
    const tracked = trackedCache.get(loc.path);

    // Group by leaf so a string holding two secrets is masked twice in its
    // suggestion, not once.
    const byLeaf = new Map();
    for (const f of found) (byLeaf.get(f.path) || byLeaf.set(f.path, []).get(f.path)).push(f);

    for (const f of found) {
      const secret = f[SECRET];
      const siblings = byLeaf.get(f.path);
      const clean = {
        ...f,
        line: lineOf(raw, secret),
        tracked,
        severity: tracked ? 'high' : 'medium',
        recommendation: (tracked ? 'This file is tracked by git, so the value is in history: rotate it, then ' : '')
          + recommendation(f.host, f.scope),
      };
      // Suggestion text, built here while the value is still in reach, and
      // only ever from masked or substituted forms of it.
      const leaf = findLeaf(doc, f);
      const masked = typeof leaf === 'string' ? maskAll(leaf, siblings) : f.masked;
      clean.leaf_masked = masked;
      clean.leaf_fixed = (ref) => (typeof leaf === 'string' ? substitute(leaf, secret, ref, siblings) : ref);
      const fix = fixSuggestion(clean);
      delete clean.leaf_masked;
      delete clean.leaf_fixed;
      clean.fix_suggestion = fix;
      findings.push(clean);
    }
  }
  return { files, unreadable, findings: findings.map(strip) };
}

/**
 * A parse error, minus the file. V8's JSON errors quote the text around the
 * fault (`Unexpected token 'o', "{ "env": { "TOKEN": "ghp_…" is not valid
 * JSON`), and in a config with a secret in it that snippet can be the
 * secret. Only the position survives.
 */
function parseErrorWithoutContent(e) {
  const msg = String((e && e.message) || '');
  if (/^line \d+: [a-z ]+$/.test(msg)) return msg;                       // ours (TOML)
  const at = msg.match(/position \d+(?: \(line \d+ column \d+\))?/);
  return at ? `not valid JSON at ${at[0]}` : 'not valid JSON';
}

function findLeaf(doc, f) {
  // Re-walk rather than parse the path back: the path is for humans.
  for (const map of serverMaps(doc, f.host)) {
    const spec = map.servers[f.server];
    if (!spec) continue;
    for (const leaf of leaves(spec, keyPath(map.base, f.server), null, null)) {
      if (leaf.path === f.path) return leaf.value;
    }
  }
  return null;
}

function maskAll(leaf, siblings) {
  let out = leaf;
  for (const s of siblings) out = out.split(s[SECRET]).join(s.masked);
  return out;
}

function substitute(leaf, secret, ref, siblings) {
  let out = leaf.split(secret).join(ref);
  for (const s of siblings) if (s[SECRET] !== secret) out = out.split(s[SECRET]).join(s.masked);
  return out;
}

/** A plain object with no symbol-keyed value on it. */
function strip(f) {
  const out = {};
  for (const k of Object.keys(f)) out[k] = f[k];
  return out;
}

// ── as findings (docs/adr/0001) ────────────────────────────────────────────

/** A config path as a subject path: relative to the project when inside it. */
function subjectPath(file, cwd) {
  if (!cwd) return file;
  const rel = path.relative(cwd, file);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel.split(path.sep).join('/') : file;
}

/**
 * A scan, as lib/finding.cjs findings over host-config subjects (`path:line`).
 * Nothing here decides: every plain-text secret is an observed
 * `secrets/<rule>` finding and the `secrets/*` row of lib/policy_rules.cjs
 * says what that means. A config that could not be read is a
 * `scope/unreadable` finding (`no-data`), never silence, and a config that was
 * read and holds nothing is still a subject — so its "allow" is an answer, not
 * an absence.
 *
 * The value stays out here too: the message is built from the same fields the
 * legacy finding already carried (type, key path, length, mask). `details`
 * keeps the advice that is not a finding — the recommendation and the
 * suggested edit — keyed by finding id.
 *
 *   -> { findings, subjects, details: [{ finding, path, key, type, length, masked, tracked, recommendation, fix_suggestion }] }
 */
function toFindings(result, { cwd = null, scope = 'host-configs' } = {}) {
  const findings = [];
  const details = [];
  const withFindings = new Set();
  for (const f of result.findings || []) {
    const s = subject.hostConfig({ path: subjectPath(f.file, cwd), line: f.line, host: f.host, scope: f.scope, server: f.server });
    const fnd = finding({
      rule: `secrets/${f.rule}`,
      subject: s,
      scope,
      severity: f.severity,
      // A known format is what it says it is; the heuristic is a name plus an
      // entropy bar, which is a good guess and no more.
      confidence: f.confidence === 'format' ? 'high' : 'medium',
      state: 'observed',
      message: `${f.type} in plain text at ${f.path} (${f.length} chars, ${f.masked})`
        + (f.tracked ? '; the file is tracked by git, so the value is in history' : ''),
    });
    findings.push(fnd);
    withFindings.add(f.file);
    details.push({
      finding: fnd.id, path: f.path, key: f.key, type: f.type, length: f.length, masked: f.masked,
      tracked: f.tracked, recommendation: f.recommendation, fix_suggestion: f.fix_suggestion || null,
    });
  }
  for (const u of result.unreadable || []) {
    findings.push(finding({
      rule: 'scope/unreadable',
      subject: subject.hostConfig({ path: subjectPath(u.path, cwd), host: u.host, scope: u.scope }),
      scope, severity: 'medium', state: 'no-data',
      message: `${subjectPath(u.path, cwd)}: ${u.error} — its servers were not scanned`,
    }));
  }
  const subjects = (result.files || []).filter((x) => !withFindings.has(x.path))
    .map((x) => subject.hostConfig({ path: subjectPath(x.path, cwd), host: x.host, scope: x.scope }));
  return { findings, subjects, details };
}

module.exports = {
  KNOWN,
  toFindings,
  subjectPath,
  scanString,
  scanServer: (spec, base, origin) => scanServer(spec, base, origin).map(strip),
  scanDocument: (doc, loc) => scanDocument(doc, loc).map(strip),
  scanHostConfigs,
  parseCodexTomlServers,
  recommendation,
  maskValue,
  redact,
  entropy,
  isSecretName,
  looksLikeSecretValue,
  gitTracked,
};
