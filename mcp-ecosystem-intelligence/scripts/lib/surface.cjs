'use strict';
/**
 * The MCP tool surface, fingerprinted — so a server changing what it exposes is
 * something we notice rather than something we find out about.
 *
 * `est_tools_count` and the eval's `tool_count_drift` catch exactly one kind of
 * change: the number moved. A server that renames a tool, rewrites a
 * description or widens an input schema keeps its count and looks identical.
 * That is the interesting case, because the tool surface is *what reaches the
 * model*: names, descriptions and schemas go into the system prompt on every
 * request, and a description is an instruction the model will follow. A package
 * that never changed while its descriptions did is the shape of a rug pull.
 *
 * What is stored is hashes, never text. Two reasons, one of them not obvious:
 *   - a diff of 1021 tool descriptions would be unreadable and enormous;
 *   - a tool description is attacker-controlled text, and committing it into
 *     this repository would put prompt-injection payloads in a file that other
 *     people's agents read. Hashes compare; they don't execute.
 *
 * The comparison that matters is between the *artifact* and the *surface*:
 *
 *   artifact changed + surface changed    an upgrade: expected, still read it
 *   artifact changed + surface unchanged  a patch release, nothing to see
 *   artifact unchanged + surface changed  the same bytes are now saying
 *                                         something different — which for a
 *                                         local server means something is not
 *                                         deterministic, and for a remote one
 *                                         means the server was changed under
 *                                         you. This is the case with no
 *                                         innocent explanation.
 *
 * API:
 *   fingerprintTools(tools)          -> { sha256, count, tools: {name: {…}} }
 *   diffSurface(before, after)       -> { added, removed, changed, unchanged }
 *   describeDiff(diff)               -> [string]        (human lines)
 *   isEmpty(diff)                    -> boolean
 */

const crypto = require('crypto');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/**
 * Canonical JSON: object keys sorted at every depth, no whitespace.
 *
 * Without this, a server that serialises its schema with keys in a different
 * order every start would look like it changed on every run — and a fingerprint
 * that cries wolf gets turned off, which is worse than not having one.
 */
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

/**
 * Fingerprint a `tools/list` result.
 *
 * Per tool: the description and the input schema are hashed separately, because
 * they fail differently. A changed schema is a capability change (a new
 * parameter, a widened enum); a changed description is an instruction change,
 * which is the one a model acts on without anybody reviewing it.
 */
function fingerprintTools(tools) {
  const list = Array.isArray(tools) ? tools : [];
  const out = {};
  for (const t of list) {
    const name = t && typeof t.name === 'string' ? t.name : null;
    if (!name) continue;
    out[name] = {
      // A missing description is not the same as an empty one: one is a server
      // that says nothing, the other a server that says "". Distinguish them,
      // so adding an empty description still registers as a change.
      description: t.description === undefined ? null : sha256(String(t.description)),
      schema:      t.inputSchema === undefined ? null : sha256(canonical(t.inputSchema)),
    };
  }
  const names = Object.keys(out).sort();
  return {
    // One hash over the whole surface: cheap to compare, and what a lockfile
    // pins. Built from the per-tool hashes so it changes iff one of them does.
    sha256: sha256(canonical(names.map((n) => [n, out[n].description, out[n].schema]))),
    count:  names.length,
    tools:  Object.fromEntries(names.map((n) => [n, out[n]])),
  };
}

/** What changed between two fingerprints. Order of arguments is before, after. */
function diffSurface(before, after) {
  const a = (before && before.tools) || {};
  const b = (after && after.tools) || {};
  const added   = Object.keys(b).filter((n) => !(n in a)).sort();
  const removed = Object.keys(a).filter((n) => !(n in b)).sort();
  const changed = [];
  let unchanged = 0;
  for (const name of Object.keys(a)) {
    if (!(name in b)) continue;
    const fields = [];
    if (a[name].description !== b[name].description) fields.push('description');
    if (a[name].schema !== b[name].schema) fields.push('schema');
    if (fields.length) changed.push({ name, fields });
    else unchanged++;
  }
  changed.sort((x, y) => (x.name < y.name ? -1 : 1));
  return { added, removed, changed, unchanged };
}

function isEmpty(diff) {
  return Boolean(diff) && !diff.added.length && !diff.removed.length && !diff.changed.length;
}

/**
 * The diff in words. A new tool is listed by name because a tool appearing is
 * the change most worth reading; changed tools name the field, because
 * "description changed" and "schema changed" are different problems.
 */
function describeDiff(diff, { limit = 8 } = {}) {
  if (!diff || isEmpty(diff)) return [];
  const lines = [];
  const list = (names) => names.slice(0, limit).join(', ') + (names.length > limit ? `, +${names.length - limit} more` : '');
  if (diff.added.length)   lines.push(`${diff.added.length} new tool${diff.added.length === 1 ? '' : 's'}: ${list(diff.added)}`);
  if (diff.removed.length) lines.push(`${diff.removed.length} tool${diff.removed.length === 1 ? '' : 's'} gone: ${list(diff.removed)}`);
  for (const c of diff.changed.slice(0, limit)) lines.push(`${c.name}: ${c.fields.join(' + ')} changed`);
  if (diff.changed.length > limit) lines.push(`…and ${diff.changed.length - limit} more changed tools`);
  return lines;
}

module.exports = { fingerprintTools, diffSurface, describeDiff, isEmpty, canonical, sha256 };
