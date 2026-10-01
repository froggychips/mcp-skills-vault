'use strict';
/**
 * What a *set* of MCP servers can do together that none of them was vetted for.
 *
 * Every other check here is about one server: is it the artifact we expected,
 * does anybody know something bad about it, what can its code do. None of them
 * notices the setup where each server is individually fine and the combination
 * is not. Two such shapes are checked:
 *
 * **Toxic flows** (after invariantlabs.ai/blog/toxic-flow-analysis, the "lethal
 * trifecta"). A session that can read content an attacker wrote, reach data the
 * user would not publish, and send something outward, is one prompt injection
 * away from an exfiltration — and that is true whether the three legs come from
 * three servers or from one. The GitHub MCP incident was a single server: a
 * public issue (untrusted) told the agent to read a private repo (private) and
 * open a PR with it (sink). A fourth label, `destructive`, gives the second
 * shape: untrusted content steering a tool that deletes or runs things.
 *
 * **Tool shadowing.** Two servers exposing `browser_click` (the DB has that
 * pair), or `read_file` and `readFile`, leave the model choosing between them by
 * description — and a host that does not namespace picks one silently. A
 * description that names *another* server's tool is the other half: that is how
 * a tool-poisoning payload reaches across servers ("before calling
 * send_message, …").
 *
 * Every label carries its evidence, and the evidence has a kind, because they
 * are not equally strong:
 *
 *   annotation  the server's own MCP hint on a tool (destructiveHint, …)
 *   tool-name   a tool name from the stored surface, matched by a rule below
 *   category    the DB category of the entry (a curated fact about the server)
 *   capability  the package's code can do it (lib/capabilities.cjs) — which
 *               says the package *can*, not that a tool exposes it to the model
 *
 * A flow whose every leg rests on something other than `capability` is
 * `confidence: 'high'` and is what a policy judges. A flow that needs a code
 * capability to complete is reported as `'low'` and never blocks: "this bundle
 * calls readFileSync somewhere" is not "the model can read your files".
 *
 * Hints and scans only ever *add* a label. `readOnlyHint: true` is the server
 * describing itself, and a missing capability is a statement about the
 * detector — same asymmetry as lib/capabilities.cjs, for the same reason.
 *
 * A server this cannot see into — not in the DB, no stored surface — is named
 * in `no_data`, never treated as contributing nothing. Nothing here touches the
 * network.
 *
 * API:
 *   LABELS                                  -> the four labels, with what each means
 *   toolLabels(name, annotations)           -> [{ label, source, tool, detail }]
 *   labelServer(member)                     -> { name, labels, tools, known, … }
 *   findFlows(labelled)                     -> [flow]
 *   findShadowing(labelled)                 -> [collision]
 *   analyseSet(members)                     -> { servers, flows, shadowing, no_data }
 *   memberFrom({ name, dbEntry, … })        -> member     (what labelServer takes)
 *   conclusions(analysis)                   -> [{ rule, severity, confidence, servers, message, advice }]
 *   grouped(items, keyOf)                   -> one line per pair of servers and kind
 *   findingsFor(analysis, { host, scope })  -> { findings, subjects, meta }   (lib/finding.cjs)
 *   judgeSets(sets, policy, asOf)           -> { findings, subjects, facts, decisions, lines }
 *   dbEntryForLaunch(tools, installCmd)     -> the DB entry the launch runs, by package
 *
 * Nothing here decides. Whether a flow blocks is the policy's (`toxicFlows`,
 * `toolShadowing`), applied by the `flows/*` / `shadowing/*` rows of
 * lib/policy_rules.cjs through decide() — docs/adr/0001.
 */

const { tokenHash } = require('./surface.cjs');
const { subject, finding, decide } = require('./finding.cjs');
const { toTypedEntry, packageKey } = require('./entry_model.cjs');

const LABELS = {
  untrusted_content: 'reads content somebody else wrote: web pages, issues, email, messages',
  private_data:      'reaches data the user would not publish: files, databases, secrets, private repos',
  public_sink:       'sends something outward: a message, a comment, a request to a URL it chooses',
  destructive:       'deletes, overwrites or runs things',
};

// ── category: a curated fact about the server ──────────────────────────────

// Only the categories whose *purpose* implies a leg. `utility` implies nothing,
// and guessing would turn the catch-all into a false trifecta.
const CATEGORY_LABELS = {
  'browser':       ['untrusted_content', 'public_sink'],
  'http':          ['untrusted_content', 'public_sink'],
  'search':        ['untrusted_content'],
  'web-scraping':  ['untrusted_content'],
  'docs':          ['untrusted_content'],
  'communication': ['untrusted_content', 'private_data', 'public_sink'],
  'vcs':           ['untrusted_content', 'private_data', 'public_sink'],
  'pm':            ['untrusted_content', 'private_data'],
  'cms':           ['private_data', 'public_sink'],
  'crm':           ['private_data'],
  'payments':      ['private_data'],
  'database':      ['private_data'],
  'filesystem':    ['private_data'],
  'memory':        ['private_data'],
  'infra':         ['private_data'],
  'ci-cd':         ['private_data'],
  'observability': ['private_data'],
};

const CATEGORY_WHY = {
  untrusted_content: 'its purpose is reading content from outside',
  private_data:      'its purpose is reaching the user\'s own data',
  public_sink:       'its purpose includes writing where others read',
};

// ── code capability: the package can, which is weaker ──────────────────────

// `network` and `env_access` are deliberately absent: nearly every server has
// both (it calls its API with a token from the environment), so mapping them
// would label everything and inform nothing.
const CAPABILITY_LABELS = {
  shell:            'destructive',
  fs_write:         'destructive',
  fs_read:          'private_data',
  credential_paths: 'private_data',
};

// ── tool name: the strongest heuristic, because it is what the model sees ──

const READ_VERBS  = new Set(['get', 'list', 'read', 'fetch', 'search', 'query', 'find', 'view', 'show', 'retrieve',
  'download', 'browse', 'lookup', 'describe', 'scrape', 'crawl', 'extract', 'open', 'load', 'cat', 'tail']);
const WRITE_VERBS = new Set(['create', 'update', 'add', 'write', 'edit', 'set', 'open', 'make', 'new']);
const OUT_VERBS   = new Set(['send', 'post', 'publish', 'comment', 'reply', 'share', 'upload', 'push', 'tweet',
  'notify', 'submit', 'invite', 'respond', 'broadcast', 'dm', 'email']);
const DESTRUCTIVE_VERBS = new Set(['delete', 'remove', 'drop', 'truncate', 'destroy', 'kill', 'terminate', 'purge',
  'wipe', 'reset', 'rm', 'uninstall', 'revoke', 'overwrite', 'erase', 'unlink']);
const EXEC_VERBS  = new Set(['exec', 'execute', 'run', 'eval', 'evaluate', 'spawn']);
const EXEC_NOUNS  = new Set(['command', 'commands', 'shell', 'script', 'code', 'terminal', 'sql',
  'javascript', 'js', 'python', 'browser', 'process', 'cmd']);

// Content somebody other than the user can write.
const EXTERNAL_NOUNS = new Set(['url', 'urls', 'web', 'webpage', 'website', 'page', 'html', 'markdown', 'issue',
  'issues', 'comment', 'comments', 'email', 'emails', 'mail', 'inbox', 'message', 'messages', 'pull', 'pr', 'prs',
  'discussion', 'discussions', 'post', 'posts', 'tweet', 'tweets', 'feed', 'rss', 'review', 'reviews',
  'notification', 'notifications', 'thread', 'threads', 'channel', 'chat', 'internet', 'news']);
// Tools whose whole job is pulling outside content in.
// `fetch` is not on the list: `fetchTokenPriceBySymbol` is an API call, not a
// web page. It counts only as a short name or beside a web noun (webFetch()).
const INGEST_TOKENS = new Set(['scrape', 'crawl', 'browse', 'navigate', 'websearch']);

const PRIVATE_NOUNS = new Set(['file', 'files', 'directory', 'dir', 'folder', 'secret', 'secrets', 'credential',
  'credentials', 'password', 'passwords', 'key', 'keys', 'env', 'environment', 'database', 'db',
  'table', 'tables', 'row', 'rows', 'record', 'records', 'sql', 'memory', 'memories', 'note', 'notes', 'document',
  'documents', 'customer', 'customers', 'contact', 'contacts', 'vault', 'log', 'logs', 'bucket', 'repository',
  'repo', 'contents', 'cookie', 'cookies', 'history']);
const ALWAYS_PRIVATE = new Set(['sql', 'secret', 'secrets', 'password', 'passwords', 'credential', 'credentials']);

// Something others will read, when written.
const PUBLIC_NOUNS = new Set(['issue', 'comment', 'pull', 'pr', 'discussion', 'gist', 'release', 'message', 'post',
  'tweet', 'page', 'wiki', 'webhook', 'email', 'mail', 'channel', 'status', 'review', 'reaction', 'thread']);
// A request to a URL the model chooses: whatever it puts in the URL has left.
// Reading a URL *is* making that request; reading "a network request" (a
// devtools log) is not, so the second set needs no other read verb beside it.
const URL_TOKENS     = new Set(['url', 'urls', 'navigate', 'curl']);
const REQUEST_TOKENS = new Set(['http', 'request', 'webhook']);

/** `browser_navigate`, `readFile`, `get-issue` → ['browser','navigate'], … */
function nameTokens(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

const any = (tokens, set) => tokens.some((t) => set.has(t));

/** `fetch`, `web_fetch_exa`, `fetch_url` — and not `fetchTokenPriceBySymbol`. */
const webFetch = (tk) => tk.includes('fetch') && (tk.length <= 2 || any(tk, EXTERNAL_NOUNS));

/**
 * Labels one tool earns from its name and its declared hints.
 *
 * The rules pair a verb with a noun where the verb alone would over-match:
 * `search_files` is not untrusted content and `create_file` is not a public
 * sink. Each result names the rule's reason, so a reader can disagree with it.
 */
function toolLabels(name, annotations = null) {
  const tk = nameTokens(name);
  const out = [];
  const add = (label, source, detail) => {
    if (!out.some((e) => e.label === label)) out.push({ label, source, tool: name, detail });
  };

  const readOther = tk.some((t) => READ_VERBS.has(t) && t !== 'fetch' && t !== 'open' && t !== 'load');
  if (any(tk, INGEST_TOKENS) || webFetch(tk) || (any(tk, READ_VERBS) && any(tk, EXTERNAL_NOUNS))) {
    add('untrusted_content', 'tool-name', `${name} reads content from outside`);
  }
  if (any(tk, ALWAYS_PRIVATE) || (any(tk, READ_VERBS) && any(tk, PRIVATE_NOUNS))) {
    add('private_data', 'tool-name', `${name} reads the user's data`);
  }
  // `get_post` and `read_email` carry an outward verb as their noun; with a
  // read verb present, the outward word is the thing being read.
  if ((any(tk, OUT_VERBS) && !any(tk, READ_VERBS)) || (any(tk, WRITE_VERBS) && any(tk, PUBLIC_NOUNS))) {
    add('public_sink', 'tool-name', `${name} writes where others read`);
  } else if (webFetch(tk) || any(tk, URL_TOKENS) || (any(tk, REQUEST_TOKENS) && !readOther)) {
    add('public_sink', 'tool-name', `${name} requests a URL it is given, so data can leave in the URL`);
  }
  if (any(tk, DESTRUCTIVE_VERBS) || (any(tk, EXEC_VERBS) && any(tk, EXEC_NOUNS)) || tk.includes('shell') || tk.includes('terminal')) {
    add('destructive', 'tool-name', `${name} deletes or runs things`);
  }

  // Hints add, never subtract: `readOnlyHint: true` is the server's claim
  // about itself, and letting it erase a name-derived label would let a
  // poisoned server talk its way out of the analysis.
  if (annotations && typeof annotations === 'object') {
    // Conflicting hints read the conservative way: `readOnlyHint` beside
    // `destructiveHint` does not cancel the destructive declaration.
    if (annotations.destructiveHint === true) {
      add('destructive', 'annotation', `${name} declares destructiveHint`);
    }
    if (annotations.openWorldHint === true) {
      add('untrusted_content', 'annotation', `${name} declares openWorldHint (interacts with external entities)`);
      if (annotations.readOnlyHint !== true) add('public_sink', 'annotation', `${name} declares openWorldHint without readOnlyHint`);
    }
  }
  return out;
}

/**
 * Label one configured server.
 *
 * `member`:
 *   name        the config key, or the DB name — what the reader recognises
 *   dbEntry     the matched DB entry, or null
 *   evalEntry   the stored eval row for that entry (for `surface`), or null
 *   capScan     the stored capability scan for the artifact, or null
 *   scoped      the launch narrows the tool set (--toolsets and friends)
 *   note        free text qualifying the data (e.g. measured on another version)
 */
function labelServer(member) {
  const { name, dbEntry = null, evalEntry = null, capScan = null, scoped = false, note = null } = member;
  const labels = {};
  const add = (e) => { (labels[e.label] ||= []).push(e); };

  const surface = evalEntry && evalEntry.surface && evalEntry.surface.tools ? evalEntry.surface.tools : null;
  const tools = surface ? Object.keys(surface).sort() : null;

  if (dbEntry && CATEGORY_LABELS[dbEntry.category]) {
    for (const label of CATEGORY_LABELS[dbEntry.category]) {
      add({ label, source: 'category', tool: null, detail: `category "${dbEntry.category}": ${CATEGORY_WHY[label]}` });
    }
  }
  if (tools) {
    for (const t of tools) for (const e of toolLabels(t, surface[t].annotations || null)) add(e);
  }
  if (capScan && capScan.found) {
    for (const [cap, label] of Object.entries(CAPABILITY_LABELS)) {
      const hit = capScan.found[cap] && capScan.found[cap][0];
      if (!hit) continue;
      add({ label, source: 'capability', tool: null,
        detail: `package code: ${cap} (${hit.file}${hit.line ? `:${hit.line}` : ''})` });
    }
  }

  return {
    name,
    db_entry: dbEntry ? dbEntry.name : null,
    category: dbEntry ? dbEntry.category || null : null,
    toolsets_hint: dbEntry && dbEntry.toolsets ? String(dbEntry.toolsets).split('#')[0].trim() : null,
    scoped: Boolean(scoped),
    // `known` is whether we could say anything at all. A server with no DB
    // entry and no surface has no labels because nobody looked, not because
    // it is harmless.
    known: Boolean(dbEntry || tools),
    tools,
    surface_mentions: surface
      ? Object.fromEntries(tools.filter((t) => Array.isArray(surface[t].mentions)).map((t) => [t, surface[t].mentions]))
      : {},
    labels,
    note,
  };
}

// ── flows ──────────────────────────────────────────────────────────────────

const strong = (evidence) => evidence.some((e) => e.source !== 'capability');

/** The per-leg view of a flow: which server, which tools, on what evidence. */
function leg(servers, label) {
  return servers
    .filter((s) => s.labels[label])
    .map((s) => {
      const ev = s.labels[label];
      return {
        server: s.name,
        tools: [...new Set(ev.filter((e) => e.tool).map((e) => e.tool))].slice(0, 8),
        tool_count: new Set(ev.filter((e) => e.tool).map((e) => e.tool)).size,
        sources: [...new Set(ev.map((e) => e.source))].sort(),
        strong: strong(ev),
        evidence: ev.slice(0, 3).map((e) => e.detail),
      };
    });
}

const FLOW_KINDS = {
  'lethal-trifecta': ['untrusted_content', 'private_data', 'public_sink'],
  'untrusted-destructive': ['untrusted_content', 'destructive'],
};

/**
 * What to do about a flow. Concrete where the DB knows how the server narrows
 * (`toolsets`), and otherwise the one move that always works: keep the legs
 * out of the same session.
 */
function adviceFor(kind, legs, single) {
  const out = [];
  const narrow = (s) => {
    if (s && s.toolsets_hint && !s.scoped) out.push(`narrow ${s.name} to the toolsets the task needs (DB hint: ${s.toolsets_hint})`);
  };
  if (single) {
    // Nothing to split: the one move is narrowing the server that has it all.
    const hint = single.toolsets_hint && !single.scoped ? ` (DB hint: ${single.toolsets_hint})` : '';
    if (kind === 'lethal-trifecta') {
      out.push(`${single.name} holds every leg by itself: narrow its tools${hint || ' (toolsets / allowedTools)'}, `
        + 'or run it in a profile with no private data and no write access');
    } else {
      const tools = (legs.destructive || []).flatMap((l) => l.tools);
      out.push(`require approval for ${single.name}'s destructive tools${tools.length ? ` (${tools.slice(0, 4).join(', ')})` : ''}, `
        + `or scope them out${hint}`);
    }
    return out;
  }
  // The legs the verdict rests on: a code capability does not make a server a
  // leg worth splitting off when a stronger one is already there.
  const names = (label) => {
    const all = legs[label] || [];
    const pick = all.some((l) => l.strong) ? all.filter((l) => l.strong) : all;
    return [...new Set(pick.map((l) => l.server))].join(', ');
  };
  if (kind === 'lethal-trifecta') {
    out.push(`keep ${names('untrusted_content')} and ${names('private_data')} in separate profiles `
      + `(different project configs or hosts), or drop the outward tools of ${names('public_sink')}`);
  } else {
    out.push(`keep ${names('untrusted_content')} out of the profile that has ${names('destructive')}, `
      + 'or require approval for its destructive tools');
  }
  const seen = new Set();
  for (const l of Object.values(legs).flat()) {
    if (seen.has(l.server)) continue;
    seen.add(l.server);
    narrow(l._server);
  }
  return out;
}

const FLOW_WORDS = {
  'lethal-trifecta': ['reads untrusted content, reaches private data and can send outward',
    'untrusted content + private data + outward sink'],
  'untrusted-destructive': ['reads untrusted content and can run destructive actions',
    'untrusted content + destructive action'],
};

/**
 * One flow per server that holds every leg by itself (the GitHub case: nothing
 * to split, only something to narrow), and otherwise one flow for the set.
 * A set where one server already closes the loop gets no second, cross-server
 * copy of the same finding.
 */
function findFlows(labelled) {
  const flows = [];
  for (const [kind, needed] of Object.entries(FLOW_KINDS)) {
    if (!needed.every((label) => labelled.some((s) => s.labels[label]))) continue;
    const confidenceOf = (servers) => (needed.every((label) => servers.some((s) => s.labels[label] && strong(s.labels[label])))
      ? 'high' : 'low');
    const setConfidence = confidenceOf(labelled);

    // A server "alone" holds every leg on evidence as strong as the set's: a
    // bundle calling readFileSync does not make a browser server the private
    // leg while a memory server sits right next to it.
    const singles = labelled.filter((s) => needed.every((label) => s.labels[label])
      && confidenceOf([s]) === setConfidence);

    const groups = singles.length ? singles.map((s) => [s]) : [labelled];
    for (const group of groups) {
      const legs = {};
      for (const label of needed) {
        legs[label] = leg(group, label).map((l) => ({ ...l, _server: group.find((s) => s.name === l.server) }));
      }
      const single = singles.length ? group[0] : null;
      const advice = adviceFor(kind, legs, single);
      for (const label of needed) legs[label] = legs[label].map(({ _server, ...rest }) => rest);
      const servers = [...new Set(needed.flatMap((label) => legs[label].map((l) => l.server)))].sort();
      flows.push({
        kind,
        confidence: confidenceOf(group),
        servers,
        single_server: Boolean(single),
        legs,
        advice,
        message: single
          ? `${single.name} alone ${FLOW_WORDS[kind][0]}`
          : `${FLOW_WORDS[kind][1]} across ${servers.join(', ')}`,
      });
    }
  }
  return flows;
}

// ── shadowing ──────────────────────────────────────────────────────────────

const normalise = (n) => String(n).toLowerCase().replace(/[^a-z0-9]/g, '');

/** Levenshtein distance, bailing out once it passes `max`. */
function editDistance(a, b, max = 1) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (cur[j] < best) best = cur[j];
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

/**
 * Tool names two servers share, or nearly share, and descriptions that name
 * another server's tool.
 *
 *   exact       the same name
 *   normalized  the same once case and separators go (read_file / readFile)
 *   near        one edit apart, both at least 6 characters (get_issue /
 *               get_issues) — reported, but `confidence: 'low'`
 *   mention     a description of one server contains the name of a tool (or
 *               of the server) of another — the cross-server poisoning shape.
 *               Only visible where the eval stored mention hashes.
 */
function findShadowing(labelled) {
  const out = [];
  const withTools = labelled.filter((s) => s.tools && s.tools.length);

  for (let i = 0; i < withTools.length; i++) {
    for (let j = i + 1; j < withTools.length; j++) {
      const a = withTools[i];
      const b = withTools[j];
      const bByNorm = new Map();
      for (const t of b.tools) (bByNorm.get(normalise(t)) || bByNorm.set(normalise(t), []).get(normalise(t))).push(t);
      const matchedB = new Set();
      for (const ta of a.tools) {
        const na = normalise(ta);
        for (const tb of bByNorm.get(na) || []) {
          matchedB.add(tb);
          out.push({
            kind: ta === tb ? 'exact' : 'normalized',
            confidence: 'high',
            tools: [{ server: a.name, tool: ta }, { server: b.name, tool: tb }],
            message: ta === tb
              ? `${a.name} and ${b.name} both expose "${ta}"`
              : `${a.name} "${ta}" and ${b.name} "${tb}" differ only in case or separators`,
          });
        }
      }
      for (const ta of a.tools) {
        const na = normalise(ta);
        if (na.length < 6 || bByNorm.has(na)) continue;
        for (const tb of b.tools) {
          const nb = normalise(tb);
          if (matchedB.has(tb) || nb.length < 6) continue;
          if (editDistance(na, nb, 1) === 1) {
            out.push({
              kind: 'near', confidence: 'low',
              tools: [{ server: a.name, tool: ta }, { server: b.name, tool: tb }],
              message: `${a.name} "${ta}" and ${b.name} "${tb}" are one edit apart`,
            });
          }
        }
      }
    }
  }

  // Mentions: hash the other servers' names and look them up. A description
  // naming a tool its own server also has is talking about itself.
  for (const a of labelled) {
    const own = new Set((a.tools || []).map((t) => t.toLowerCase()));
    for (const [tool, hashes] of Object.entries(a.surface_mentions || {})) {
      const set = new Set(hashes);
      for (const b of labelled) {
        if (b === a) continue;
        const targets = [...(b.tools || []).map((t) => ({ what: 'tool', name: t })),
          { what: 'server', name: b.name }, ...(b.db_entry && b.db_entry !== b.name ? [{ what: 'server', name: b.db_entry }] : [])];
        for (const t of targets) {
          if (own.has(t.name.toLowerCase())) continue;
          if (!set.has(tokenHash(t.name))) continue;
          out.push({
            kind: 'mention', confidence: 'high',
            tools: [{ server: a.name, tool }, { server: b.name, tool: t.what === 'tool' ? t.name : null }],
            message: `the description of ${a.name} "${tool}" names ${t.what === 'tool' ? `${b.name}'s tool "${t.name}"` : `the server ${t.name}`}`,
          });
        }
      }
    }
  }
  return out;
}

// ── the set ────────────────────────────────────────────────────────────────

/**
 * Both analyses over one set of servers — one host's session, since servers in
 * different hosts never share a context.
 */
function analyseSet(members) {
  const labelled = members.map(labelServer);
  const flows = findFlows(labelled);
  const shadowing = findShadowing(labelled);
  return {
    servers: labelled.map((s) => ({
      name: s.name,
      db_entry: s.db_entry,
      category: s.category,
      known: s.known,
      scoped: s.scoped,
      tool_names: s.tools ? 'stored' : 'none',
      labels: Object.fromEntries(Object.entries(s.labels).map(([label, ev]) => [label, ev.map(({ label: _l, ...e }) => e)])),
      note: s.note,
    })),
    flows,
    shadowing,
    // Named, so "no flow found" is never read as a claim about these.
    no_data: labelled.filter((s) => !s.known).map((s) => s.name),
    // Servers whose labels come only from the DB category: tool-level
    // shadowing and per-tool legs could not be checked for them.
    no_tool_names: labelled.filter((s) => s.known && !s.tools).map((s) => s.name),
  };
}

// The launch flags that narrow a server's tools — same vocabulary as the
// audit's heavy-unbounded check.
const SCOPE_FLAG = /(^|\s)--(toolsets|caps|disabledTools|tools|read-only)(=|\s|$)/;

/**
 * Build one member from what a caller has already matched. `artifactIds` is
 * tried in order for the capability scan — the installed artifact first, then
 * the vault's, which is labelled as being about another version.
 */
function memberFrom({ name, dbEntry = null, evalEntry = null, capabilities = null, artifactIds = [], launch = null, note = null }) {
  const packages = (capabilities && capabilities.packages) || {};
  let capScan = null;
  const notes = note ? [note] : [];
  for (const [i, id] of artifactIds.entries()) {
    if (id && packages[id]) {
      capScan = packages[id];
      if (i > 0) notes.push(`code capabilities scanned on ${id}`);
      break;
    }
  }
  return {
    name, dbEntry, evalEntry, capScan,
    scoped: Boolean(launch && SCOPE_FLAG.test(launch)),
    note: notes.length ? notes.join('; ') : null,
  };
}

/**
 * The analysis as a flat list of conclusions: one per flow, one per shadowing
 * collision. Each says which servers and tools it is about, how sure it is,
 * and what to do — and nothing about whether it blocks. That is `decide()`
 * over the rows `flows/*` / `shadowing/*` in lib/policy_rules.cjs, which read
 * the policy keys `toxicFlows` / `toolShadowing` and do not enforce a
 * low-confidence conclusion.
 */
const SHADOW_SEVERITY = { exact: 'medium', normalized: 'medium', near: 'low', mention: 'high' };

function conclusions(analysis) {
  const out = [];
  for (const f of analysis.flows) {
    out.push({
      rule: `flows/${f.kind}`, kind: f.kind, severity: 'high', confidence: f.confidence,
      servers: f.servers, tools: [], message: f.message, advice: f.advice[0] || null,
    });
  }
  for (const c of analysis.shadowing) {
    const [a, b] = c.tools.map((t) => t.server);
    out.push({
      rule: `shadowing/${c.kind}`, kind: c.kind, severity: SHADOW_SEVERITY[c.kind] || 'medium', confidence: c.confidence,
      servers: [a, b], tools: c.tools, message: c.message,
      advice: c.kind === 'mention'
        ? `read ${a}'s descriptions before trusting it beside ${b}; a description that steers another server's tool is the tool-poisoning shape`
        : `keep one of ${a} / ${b} per profile, or disable the duplicated tools in one of them`,
    });
  }
  return out;
}

/**
 * Collisions of one pair of servers, of one kind (and, for a rendering, one
 * effect), as one line: two browser servers sharing six names is one thing
 * for a reader, not six. Flows pass through unchanged.
 */
function grouped(items, keyOf = () => '') {
  const out = [];
  const groups = new Map();
  for (const it of items) {
    if (!it.rule.startsWith('shadowing/')) { out.push({ ...it, items: [it] }); continue; }
    const key = `${it.rule}\u0000${it.servers.join('\u0000')}\u0000${keyOf(it)}`;
    if (!groups.has(key)) { groups.set(key, { ...it, items: [] }); out.push(groups.get(key)); }
    groups.get(key).items.push(it);
  }
  for (const g of out) {
    if (g.items.length < 2) continue;
    const [a, b] = g.servers;
    const names = g.items.map((c) => c.tools[0].tool);
    const list = names.slice(0, 4).join(', ') + (names.length > 4 ? `, +${names.length - 4}` : '');
    g.message = g.kind === 'mention'
      ? `${g.items.length} tool descriptions of ${a} name tools or the server of ${b} (${list})`
      : `${a} and ${b} share ${g.items.length} ${g.kind === 'near' ? 'near-identical ' : ''}tool names: ${list}`;
  }
  return out;
}

/**
 * One host's analysis as findings (lib/finding.cjs). A flow is about the
 * session (`setup` subject, the host); a collision is about the tool that
 * collides (`tool` subject, located at the host, so the same server in two
 * hosts is two subjects). A server nobody could see into is a `no-data`
 * finding on the session: "no flow found" is not a claim about it.
 *
 * Returns { findings, subjects, meta } — `meta` maps a finding id to the
 * servers and advice a rendering shows beside it; neither is a decision.
 */
function findingsFor(analysis, { host, scope = null } = {}) {
  const setupSubject = subject.setup({ host: host || 'unknown', scope });
  const findings = [];
  const meta = {};
  const push = (f, m) => { findings.push(f); meta[f.id] = m; };
  for (const c of conclusions(analysis)) {
    const subj = c.rule.startsWith('flows/') ? setupSubject
      : subject.tool({ server: c.tools[0].server, tool: c.tools[0].tool, location: setupSubject.id });
    push(finding({ rule: c.rule, subject: subj, scope, severity: c.severity, confidence: c.confidence, message: c.message }),
      { host: setupSubject.id, rule: c.rule, kind: c.kind, servers: c.servers, tools: c.tools, advice: c.advice });
  }
  for (const name of analysis.no_data) {
    push(finding({
      rule: 'flows/no-data', subject: setupSubject, scope, severity: 'info', state: 'no-data',
      message: `${name}: not in the vault and no stored tool surface — what it adds to this session is unknown`,
    }), { host: setupSubject.id, rule: 'flows/no-data', kind: 'no-data', servers: [name], tools: [], advice: null });
  }
  const subjects = [setupSubject];
  for (const f of findings) if (!subjects.some((s) => s.id === f.subject.id)) subjects.push(f.subject);
  return { findings, subjects, meta };
}

/**
 * Several hosts' analyses → findings, `decide()`'s Decisions over them, and
 * the rendering a command prints: one line per rule outcome (collisions of
 * one pair grouped), carrying the effect the Decision gave it. A command
 * shows these lines; it does not re-derive them from the policy.
 *
 *   sets     [{ host, scope, analysis }]
 *   policy   the frozen effective policy (lib/policy_rules.cjs)
 *   asOf     the instant decided at (lib/clock.cjs)
 */
function judgeSets(sets, policy, asOf) {
  const findings = [];
  const subjects = [];
  const meta = {};
  for (const { host, scope = null, analysis } of sets) {
    const r = findingsFor(analysis, { host, scope });
    findings.push(...r.findings);
    for (const s of r.subjects) if (!subjects.some((x) => x.id === s.id)) subjects.push(s);
    Object.assign(meta, r.meta);
  }
  // `mode: setup` is a fact of each subject, so a findings@1 document of
  // these decisions reproduces them from its own inputs.
  const facts = Object.fromEntries(subjects.map((s) => [s.id, { mode: 'setup' }]));
  const decisions = decide(findings, policy, asOf, { subjects, facts, mode: 'setup' });
  const byId = new Map(findings.map((f) => [f.id, f]));
  const items = [];
  for (const d of decisions) {
    for (const o of d.rules) {
      for (const id of o.findings) {
        const m = meta[id];
        const f = byId.get(id);
        if (!m || !f) continue;
        items.push({ ...m, rule: o.rule, effect: o.effect, message: f.message, finding: id });
      }
    }
  }
  const lines = grouped(items, (it) => `${it.host}\u0000${it.effect}`)
    .map(({ items: members, ...it }) => ({ ...it, findings: members.map((x) => x.finding) }));
  return { findings, subjects, facts, decisions, lines };
}

/**
 * The vault entry a configured launch runs, matched by package identity. The
 * config key is the user's label: a server keyed `github-mcp-server` that runs
 * `node innocent.js` is not the vault's GitHub server and must not inherit
 * its labels.
 */
function dbEntryForLaunch(tools, installCmd) {
  if (!installCmd) return null;
  let key = null;
  try { const t = toTypedEntry({ install_cmd: installCmd }); key = t ? packageKey(t.artifact) : null; } catch { key = null; }
  if (!key) return null;
  return (tools || []).find((tool) => {
    try { const t = toTypedEntry(tool); return Boolean(t && packageKey(t.artifact) === key); } catch { return false; }
  }) || null;
}

module.exports = {
  LABELS, CATEGORY_LABELS, CAPABILITY_LABELS, FLOW_KINDS,
  nameTokens, toolLabels, labelServer, findFlows, findShadowing, analyseSet,
  conclusions, grouped, findingsFor, judgeSets, dbEntryForLaunch, memberFrom, editDistance, normalise,
};
