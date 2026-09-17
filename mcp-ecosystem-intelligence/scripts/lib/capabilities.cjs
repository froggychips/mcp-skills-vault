'use strict';
/**
 * What a package is *able* to do, and what changed since last time.
 *
 * Everything else in this repo answers "is this the artifact we expected" and
 * "does anybody know something bad about this version". Neither notices a patch
 * release that starts reading `process.env` and shelling out — which is what a
 * compromised release looks like *before* it has a CVE, and the window in which
 * an advisory feed is useless.
 *
 * The honest shape of this check is the whole design, because static analysis of
 * JavaScript is easy to evade and most npm packages ship a minified bundle:
 *
 *   **`found` is a fact. `absent` is never recorded.**
 *
 * A capability found with a file and a line is evidence. A capability *not*
 * found is a statement about our detector, not about the package — obfuscated
 * code, a dynamic `require`, or a string built at runtime all defeat it. So the
 * output has a `found` map with evidence and a `coverage` block describing what
 * was actually read, and nothing in it ever says a package cannot do something.
 *
 * That asymmetry decides how the delta works too: **additions are reported,
 * removals are not treated as improvements.** An added capability is robust to
 * holes in the detector (it fired on real text); a disappeared one is as likely
 * to mean the code got harder to read as it is to mean the behaviour went away.
 *
 * API:
 *   detect(files, packageJson)   -> { found, coverage, notes }
 *   diffCapabilities(a, b)       -> { added, removed, coverage_changed }
 *   CAPABILITIES                 -> the detectors, with what each one means
 *   HIGH_RISK                    -> the subset worth failing a build over
 */

// Each detector: a pattern, and why the capability matters for an MCP server
// specifically. The patterns are deliberately conservative — a false "found"
// costs a reviewer a minute, and a missed one is covered by never claiming
// absence.
const CAPABILITIES = {
  shell: {
    why: 'runs other programs; an MCP server that shells out can do anything the user can',
    patterns: [
      /\brequire\s*\(\s*['"](?:node:)?child_process['"]\s*\)/,
      /\bfrom\s+['"](?:node:)?child_process['"]/,
      // Not `.exec(` — `/re/.exec(s)` and `str.match(…).exec` are regex and
      // string methods, and reporting them as shell execution put a
      // *build-stopping* high-risk finding on ordinary code. A real
      // child_process call is either preceded by the import above (which
      // matches the same file) or reached through a binding, so requiring
      // something other than a dot in front costs almost nothing and removes
      // the whole false-positive class.
      /(?:^|[^.\w$])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/m,
    ],
  },
  network: {
    why: 'reaches the network; the difference between a local tool and a data exfiltration path',
    patterns: [
      /\brequire\s*\(\s*['"](?:node:)?(?:http|https|net|tls|dgram)['"]\s*\)/,
      /\bfrom\s+['"](?:node:)?(?:http|https|net|tls|dgram)['"]/,
      /\bfetch\s*\(/,
      /\bnew\s+WebSocket\s*\(/,
      /\bXMLHttpRequest\b/,
      /\b(?:axios|undici|node-fetch|got)\b/,
    ],
  },
  fs_read: {
    why: 'reads files; scope matters more than presence for a filesystem server',
    patterns: [
      /\bfs\.(?:readFile|readFileSync|createReadStream|readdir|readdirSync|realpath)\b/,
      /\b(?:readFile|readFileSync|createReadStream)\s*\(/,
    ],
  },
  fs_write: {
    why: 'writes or deletes files',
    patterns: [
      /\bfs\.(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|chmod|chmodSync|rename|renameSync)\b/,
      /\b(?:writeFileSync|appendFileSync|unlinkSync|rmSync)\s*\(/,
    ],
  },
  env_access: {
    why: 'reads the environment, which is where every token in a developer shell lives',
    patterns: [/\bprocess\.env\b/],
  },
  dynamic_code: {
    why: 'evaluates code built at runtime — the thing that makes static analysis of the rest unreliable',
    patterns: [
      /\beval\s*\(/,
      /\bnew\s+Function\s*\(/,
      /\brequire\s*\(\s*['"](?:node:)?vm['"]\s*\)/,
      /\bvm\.(?:runInNewContext|runInThisContext|compileFunction)\b/,
    ],
  },
  dynamic_require: {
    why: 'loads a module named at runtime, so the import graph is not knowable from the text',
    // `require(variable)` and `require(`${x}`)`, not `require('literal')`.
    //
    // The first version put the lookahead after `\s*`, which backtracks: for
    // `require( "fs")` the engine matched zero spaces, saw a space rather than
    // the quote, and reported a literal require as dynamic. The first
    // *non-space* character has to be the thing that is tested.
    patterns: [
      // An identifier or expression: the first non-space character is not a
      // quote of any kind.
      /\brequire\s*\(\s*(?=[^\s'"`])[^)]{1,60}\)/,
      // A template literal *with interpolation* — `require(`${dir}/x`)` is
      // dynamic, while `require(`fs`)` is a literal written oddly.
      /\brequire\s*\(\s*`[^`]*\$\{/,
    ],
  },
  credential_paths: {
    why: 'mentions a path where credentials live; almost never legitimate in a published package',
    // The one detector that fires on a *mention*, so a documentation link
    // mentioning `.aws/credentials` must not become a high-risk finding.
    ignoreComments: true,
    patterns: [
      /\.ssh\/(?:id_[a-z0-9]+|authorized_keys|config)/,
      /\.aws\/credentials/,
      /\.npmrc\b/,
      /\.docker\/config\.json/,
      /\.kube\/config/,
      /\.git-credentials/,
      /\bkeychain\b/i,
      /\.config\/gh\/hosts\.yml/,
    ],
  },
  install_script: {
    why: 'runs code at install time, before anybody has decided to launch it',
    // Detected from package.json, not from source text.
    patterns: [],
  },
};

// The capabilities whose *appearance* in a new version is worth stopping a
// build for. Network and file access are what MCP servers are for; shelling
// out, evaluating runtime-built code, reading credential paths and running at
// install time are not.
const HIGH_RISK = new Set(['shell', 'dynamic_code', 'credential_paths', 'install_script']);

const CODE_FILE = /\.(?:js|cjs|mjs|jsx|ts|tsx|mts|cts)$/i;

/** Line number of an offset, for evidence a human can go and look at. */
function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

/**
 * How readable was what we read?
 *
 * This exists so that "nothing found" can be qualified honestly. A 900 KB
 * single-line bundle and a 40-line server are both "scanned", and a reader
 * needs to know which one they are being told about.
 */
function coverageOf(files) {
  const code = files.filter((f) => CODE_FILE.test(f.path));
  const bytes = code.reduce((n, f) => n + (f.text ? f.text.length : 0), 0);
  let longestLine = 0;
  let totalLines = 0;
  let base64Blobs = 0;
  let escapeHeavy = 0;
  // Per file, because the question is "is any of the shipped code unreadable",
  // not "is the average readable". A package-wide average let one 3.6 KB
  // single-line bundle be classified as readable as soon as a second file with
  // a hundred newlines was added beside it — no executable code became any
  // more readable, and the caveat printed next to "nothing found" got weaker.
  const minifiedFiles = [];

  for (const f of code) {
    const lines = f.text.split('\n');
    totalLines += lines.length;
    let fileLongest = 0;
    for (const l of lines) if (l.length > fileLongest) fileLongest = l.length;
    if (fileLongest > longestLine) longestLine = fileLongest;
    const fileAvg = lines.length ? Math.round(f.text.length / lines.length) : 0;
    if (f.text.length > 1000 && (fileLongest > 5000 || fileAvg > 400)) minifiedFiles.push(f.path);
    // A long base64 run is a payload, not code. Not a capability on its own,
    // but it is the reason a scan can be complete and still see nothing.
    for (const m of f.text.match(/[A-Za-z0-9+/]{512,}={0,2}/g) || []) base64Blobs += m.length;
    const escapes = (f.text.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/gi) || []).length;
    if (f.text.length > 2000 && escapes / f.text.length > 0.02) escapeHeavy++;
  }

  const avgLine = totalLines ? Math.round(bytes / totalLines) : 0;
  const minified = minifiedFiles.length > 0;

  return {
    code_files: code.length,
    other_files: files.length - code.length,
    bytes,
    longest_line: longestLine,
    avg_line_length: avgLine,
    minified,
    // Named, so "minified" is a statement about specific files rather than a
    // mood about the package.
    minified_files: minifiedFiles.slice(0, 10),
    base64_bytes: base64Blobs,
    escape_heavy_files: escapeHeavy,
    // The sentence a report should print next to any "not found".
    caveat: minified
      ? `${minifiedFiles.length} of ${code.length} code file(s) are written for a machine; a pattern scan over them can show presence, never absence`
      : 'a pattern scan can show presence, never absence',
  };
}

/**
 * Scan a package's files.
 *
 * `files` is [{ path, text }] as lib/tarball.cjs returns. `packageJson` is the
 * parsed manifest, used only for install scripts — which are a capability
 * declared rather than detected, and the most reliable signal here.
 */
/**
 * Text that is documentation rather than behaviour.
 *
 * `// See https://example.org/docs/.aws/credentials` produced a high-risk
 * `credential_paths` finding — a fact, with evidence, able to stop a build —
 * for a comment. Line comments and URLs are stripped before the
 * credential-path patterns run. Block comments and string literals are *not*
 * stripped: doing that properly needs a parser, and the point of this module is
 * that it is a pattern scan which says so.
 */
function withoutCommentsAndUrls(text) {
  return text
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/, '').replace(/https?:\/\/\S+/g, ' '))
    .join('\n');
}

function detect(files, packageJson = null) {
  const found = {};
  const notes = [];
  const add = (cap, file, line, snippet) => {
    found[cap] = found[cap] || [];
    // Three examples is enough to act on; more is noise in a diff.
    if (found[cap].length < 3) found[cap].push({ file, line, match: snippet.slice(0, 80) });
  };

  for (const f of files) {
    if (!CODE_FILE.test(f.path) || typeof f.text !== 'string') continue;
    // Computed once per file, not per pattern.
    const prose = withoutCommentsAndUrls(f.text);
    for (const [cap, spec] of Object.entries(CAPABILITIES)) {
      const haystack = spec.ignoreComments ? prose : f.text;
      for (const pattern of spec.patterns) {
        const m = pattern.exec(haystack);
        if (m) { add(cap, f.path, lineOf(haystack, m.index), m[0].trim()); break; }
      }
    }
  }

  // Install scripts: declared in the manifest, so this one is not a guess.
  const scripts = (packageJson && packageJson.scripts) || {};
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish']) {
    if (scripts[hook]) {
      found.install_script = found.install_script || [];
      found.install_script.push({ file: 'package.json', line: null, match: `${hook}: ${String(scripts[hook]).slice(0, 60)}` });
    }
  }

  if (packageJson && packageJson.bin && typeof packageJson.bin === 'object' && Object.keys(packageJson.bin).length > 1) {
    notes.push(`declares ${Object.keys(packageJson.bin).length} executables`);
  }

  return { found, coverage: coverageOf(files), notes };
}

/**
 * What changed between two scans of the same package.
 *
 * Additions are findings. Removals are reported but explicitly not treated as
 * improvements: a capability that stopped matching is as likely to mean the
 * code became less readable — a new bundler, a minifier, an obfuscator — as it
 * is to mean the behaviour went away. Saying "network access removed" on the
 * strength of a pattern that stopped firing would be exactly the kind of claim
 * this module refuses to make.
 */
function diffCapabilities(before, after) {
  const a = new Set(Object.keys((before && before.found) || {}));
  const b = new Set(Object.keys((after && after.found) || {}));

  const added = [...b].filter((cap) => !a.has(cap)).sort();
  const removed = [...a].filter((cap) => !b.has(cap)).sort();

  const beforeCov = (before && before.coverage) || {};
  const afterCov  = (after && after.coverage) || {};
  const coverageChanged = Boolean(beforeCov.minified !== afterCov.minified)
    || (beforeCov.bytes && afterCov.bytes && Math.abs(afterCov.bytes - beforeCov.bytes) / beforeCov.bytes > 0.5);

  return {
    added: added.map((cap) => ({
      capability: cap,
      why: CAPABILITIES[cap] ? CAPABILITIES[cap].why : null,
      high_risk: HIGH_RISK.has(cap),
      evidence: (after.found[cap] || []).slice(0, 3),
    })),
    // Deliberately not called "resolved" or "fixed".
    removed: removed.map((cap) => ({
      capability: cap,
      note: 'stopped matching — this may mean the code changed, or only that it became harder to read',
    })),
    coverage_changed: coverageChanged,
    coverage_note: coverageChanged
      ? `what was scanned changed shape (${beforeCov.minified ? 'minified' : 'readable'} → ${afterCov.minified ? 'minified' : 'readable'}, `
        + `${beforeCov.bytes || 0} → ${afterCov.bytes || 0} bytes), so the comparison is weaker than usual`
      : null,
  };
}

module.exports = { CAPABILITIES, HIGH_RISK, detect, diffCapabilities, coverageOf, lineOf, withoutCommentsAndUrls, CODE_FILE };
