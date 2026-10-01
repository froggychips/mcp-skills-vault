'use strict';
/**
 * Tool-by-tool approval: a server's tools reach the model because somebody
 * approved *those* tools, not because the package that ships them verified.
 *
 * The lockfile already records a tool-surface fingerprint (lib/surface.cjs),
 * and `lock` rewrites it on every run — so the baseline moved whenever the
 * surface did, and "the tools changed" was only ever noticed by whoever read the
 * diff of a regenerated file. For an organisation that wants the MCP-security
 * guidance's "pin tool definitions" property, the baseline has to be something
 * only a person can move:
 *
 *   tool_approvals   a top-level section of mcp.lock.json, per server, per tool:
 *                    the description and schema hashes somebody approved. `lock`
 *                    carries it over untouched; only `mcp-vault approve` writes
 *                    it. It is committed, so the approval is a reviewable diff
 *                    with an author. Each record names the `artifact_id` it
 *                    was made on: an upgrade needs a new approval, because
 *                    the new version's tools are not the ones anyone saw.
 *
 * A tool that is new, or whose description or schema hash differs from the
 * approved one, is *pending*, and with `toolApproval: "require"` a pending tool
 * blocks the gate. A tool that disappeared is reported and never blocks: losing
 * a tool grants nothing.
 *
 * What is stored follows surface.cjs's rule — hashes, never text: a tool
 * description is attacker-controlled text, and committing it would put
 * prompt-injection payloads in a file other people's agents read. Two small,
 * non-executable facts are kept beside the hashes so that a later change can be
 * *described* and not merely detected:
 *
 *   description_chars  the length, so "grew from 120 to 4,000 characters" can be
 *                      said without keeping the words
 *   params / required  the top-level parameter names and JSON types of the
 *                      input schema, names reduced to a safe alphabet (anything
 *                      else is stored as a hash), types from a fixed vocabulary
 *
 * Those two exist only when the approval was made from a raw tools/list
 * (`--tools <file>`); from eval results, which hold hashes, only the hashes are
 * recorded and the diff says so rather than inventing detail.
 *
 * API:
 *   parseToolsFile(doc)                 -> [tool] | null
 *   observeTools(tools)                 -> { fingerprint, shapes, texts, chars }
 *   observationFromSurface(surface)     -> same shape, hashes only
 *   pendingTools(approved, observation) -> { added, removed, changed, unchanged }
 *   approvalFor(approved, artifactId)   -> approved | null (made on another artifact)
 *   approve(approved, observation, { tools, now, artifactId })
 *                                       -> { record, approved, remaining, dropped }  (now required)
 *   describePending(pending, approved, observation) -> [{ tool, change, … }]
 *   describeLines(details)              -> [string]
 *   APPROVALS_KEY
 */

const { fingerprintTools, diffSurface, sha256 } = require('./surface.cjs');
const { requireAsOf, isoDay } = require('./clock.cjs');
const { comparableId } = require('./entry_model.cjs');

const APPROVALS_KEY = 'tool_approvals';

// A parameter name that is an identifier is kept; anything else could be text,
// and text is what this file refuses to store.
const SAFE_NAME = /^[A-Za-z0-9_.:-]{1,64}$/;
const safeName = (n) => (SAFE_NAME.test(String(n)) ? String(n) : `#${sha256(String(n)).slice(0, 12)}`);

const JSON_TYPES = new Set(['string', 'number', 'integer', 'boolean', 'array', 'object', 'null']);

function typeOf(schema) {
  if (!schema || typeof schema !== 'object') return 'any';
  if (Array.isArray(schema.type)) {
    const t = schema.type.map(String).filter((x) => JSON_TYPES.has(x)).sort();
    return t.length ? t.join('|') : 'other';
  }
  if (typeof schema.type === 'string') return JSON_TYPES.has(schema.type) ? schema.type : 'other';
  if (Array.isArray(schema.enum)) return 'enum';
  if (schema.$ref) return 'ref';
  if (schema.anyOf || schema.oneOf || schema.allOf) return 'union';
  return 'any';
}

/** Top-level parameters and their types. Deeper structure is only hashed. */
function schemaShape(inputSchema) {
  if (!inputSchema || typeof inputSchema !== 'object') return null;
  const props = inputSchema.properties && typeof inputSchema.properties === 'object' ? inputSchema.properties : {};
  const params = {};
  for (const k of Object.keys(props).sort()) params[safeName(k)] = typeOf(props[k]);
  const required = Array.isArray(inputSchema.required)
    ? [...new Set(inputSchema.required.filter((r) => typeof r === 'string').map(safeName))].sort()
    : [];
  return { params, required };
}

/** A tools/list result in any of the shapes it is usually saved in. */
function parseToolsFile(doc) {
  if (Array.isArray(doc)) return doc;
  if (doc && Array.isArray(doc.tools)) return doc.tools;
  if (doc && doc.result && Array.isArray(doc.result.tools)) return doc.result.tools;
  return null;
}

/** What a raw tools/list says: hashes to compare, plus what a diff can print. */
function observeTools(tools) {
  const fingerprint = fingerprintTools(tools);
  const shapes = {};
  const texts = {};
  const chars = {};
  for (const t of Array.isArray(tools) ? tools : []) {
    if (!t || typeof t.name !== 'string' || !(t.name in fingerprint.tools)) continue;
    shapes[t.name] = schemaShape(t.inputSchema);
    // Kept in memory for the terminal and --json, never written to the lock.
    texts[t.name] = t.description === undefined ? null : String(t.description);
    chars[t.name] = t.description === undefined ? null : String(t.description).length;
  }
  return { fingerprint, shapes, texts, chars, detailed: true };
}

/** An observation from a stored fingerprint (eval results): hashes only. */
function observationFromSurface(surface) {
  if (!surface || !surface.tools) return null;
  return { fingerprint: surface, shapes: {}, texts: {}, chars: {}, detailed: false };
}

function pendingTools(approved, observation) {
  return diffSurface({ tools: (approved && approved.tools) || {} }, observation.fingerprint);
}

/**
 * The approval as it applies to `artifactId`: itself, or null when it was
 * made on a different artifact. Either side unknown cannot contradict the
 * other, so the approval stands.
 */
function approvalFor(approved, artifactId) {
  if (!approved) return null;
  if (!approved.artifact_id || !artifactId) return approved;
  return comparableId(approved.artifact_id) === comparableId(artifactId) ? approved : null;
}

function hasPending(pending) {
  return Boolean(pending) && (pending.added.length > 0 || pending.changed.length > 0);
}

function toolRecord(name, observation, today) {
  const fp = observation.fingerprint.tools[name];
  const rec = { description: fp.description, schema: fp.schema, approved_at: today };
  if (observation.chars[name] !== undefined) rec.description_chars = observation.chars[name];
  const shape = observation.shapes[name];
  if (shape) { rec.params = shape.params; rec.required = shape.required; }
  return rec;
}

/**
 * Approve what is pending — all of it, or only the named tools.
 *
 * Approving everything replaces the approved set with what was observed, which
 * also drops approvals for tools that are gone. Approving some leaves the rest
 * pending and keeps every other approval as it was: a partial approval is a
 * statement about those tools and nothing else.
 */
function approve(approved, observation, { tools = null, now, artifactId = null } = {}) {
  // When the approval was made is an observation, not a decision: the caller
  // reads the wall clock (lib/clock.cjs readWallClock) and passes it.
  const today = isoDay(requireAsOf(now, 'approve'));
  // An approval of another artifact is not carried over: after an upgrade
  // every tool is pending again, and a partial approval starts from nothing.
  const base = approvalFor(approved, artifactId);
  const pending = pendingTools(base, observation);
  const pendingNames = [...pending.added, ...pending.changed.map((c) => c.name)].sort();
  const current = { ...((base && base.tools) || {}) };

  let chosen;
  if (tools && tools.length) {
    const unknown = tools.filter((t) => !(t in observation.fingerprint.tools));
    if (unknown.length) return { error: `not offered by this server: ${unknown.join(', ')}` };
    chosen = [...new Set(tools)].sort();
  } else {
    chosen = pendingNames;
  }

  const dropped = [];
  if (!tools || !tools.length) {
    for (const name of pending.removed) { delete current[name]; dropped.push(name); }
  }
  for (const name of chosen) current[name] = toolRecord(name, observation, today);

  const sorted = Object.fromEntries(Object.keys(current).sort().map((n) => [n, current[n]]));
  return {
    record: { approved_at: today, artifact_id: artifactId || null, count: Object.keys(sorted).length, tools: sorted },
    approved: chosen.filter((n) => pendingNames.includes(n)),
    remaining: pendingNames.filter((n) => !chosen.includes(n)),
    dropped,
  };
}

function shapeDiff(before, after) {
  const bp = before.params || {};
  const ap = after.params || {};
  const breq = new Set(before.required || []);
  const areq = new Set(after.required || []);
  return {
    params_added:     Object.keys(ap).filter((p) => !(p in bp)).sort().map((p) => ({ param: p, type: ap[p], required: areq.has(p) })),
    params_removed:   Object.keys(bp).filter((p) => !(p in ap)).sort(),
    type_changed:     Object.keys(ap).filter((p) => p in bp && bp[p] !== ap[p]).sort().map((p) => ({ param: p, from: bp[p], to: ap[p] })),
    required_added:   [...areq].filter((p) => !breq.has(p) && p in bp).sort(),
    required_removed: [...breq].filter((p) => !areq.has(p) && p in ap).sort(),
  };
}

/** What changed, per tool, in as much detail as both sides recorded. */
function describePending(pending, approved, observation) {
  const prev = (approved && approved.tools) || {};
  const out = [];
  const textOf = (name) => (observation.texts[name] === undefined ? undefined : observation.texts[name]);
  for (const name of pending.added) {
    const shape = observation.shapes[name] || null;
    out.push({
      tool: name, change: 'added', fields: ['description', 'schema'],
      description: { before_chars: null, after_chars: observation.chars[name] ?? null, text: textOf(name) },
      schema: shape ? { params: shape.params, required: shape.required } : null,
    });
  }
  for (const c of pending.changed) {
    const before = prev[c.name] || {};
    const item = { tool: c.name, change: 'changed', fields: c.fields };
    if (c.fields.includes('description')) {
      item.description = {
        before_chars: before.description_chars ?? null,
        after_chars: observation.chars[c.name] ?? null,
        text: textOf(c.name),
      };
    }
    if (c.fields.includes('schema')) {
      const after = observation.shapes[c.name] || null;
      const had = before.params ? { params: before.params, required: before.required || [] } : null;
      item.schema = had && after ? shapeDiff(had, after) : { unavailable: !had ? 'approved' : 'observed' };
    }
    out.push(item);
  }
  for (const name of pending.removed) out.push({ tool: name, change: 'removed', fields: [] });
  return out;
}

/** Attacker-controlled text, made safe to print: one line, quoted, bounded. */
function quote(text, limit = 300) {
  const flat = String(text).replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, ' ');
  return JSON.stringify(flat.length > limit ? `${flat.slice(0, limit)}…` : flat);
}

/**
 * The details as lines. Where only hashes were observed, the lines say which
 * field changed and nothing more; the caller says once how to see more
 * (`HASHES_ONLY_NOTE`) rather than on every tool.
 */
const HASHES_ONLY_NOTE = 'only hashes were observed — pass --tools <tools.json> (a saved tools/list) to see descriptions and parameters';

function describeLines(details) {
  const lines = [];
  for (const d of details) {
    if (d.change === 'removed') { lines.push(`- ${d.tool}  no longer offered (never blocks)`); continue; }
    if (d.change === 'added') {
      lines.push(`+ ${d.tool}  new tool`);
      if (d.description && d.description.text !== undefined) {
        lines.push(`    description${d.description.after_chars !== null ? ` (${d.description.after_chars} chars)` : ''}: ${d.description.text === null ? '(none)' : quote(d.description.text)}`);
      }
      if (d.schema) {
        const params = Object.entries(d.schema.params)
          .map(([p, t]) => `${p}:${t}${d.schema.required.includes(p) ? '*' : ''}`);
        lines.push(`    params: ${params.length ? params.join(', ') : '(none)'}${params.some((p) => p.endsWith('*')) ? '   (* required)' : ''}`);
      }
      continue;
    }
    lines.push(`~ ${d.tool}  ${d.fields.join(' + ')} changed`);
    if (d.description) {
      const b = d.description.before_chars;
      const a = d.description.after_chars;
      if (b !== null && a !== null) lines.push(`    description: ${b} → ${a} chars`);
      if (d.description.text !== undefined) lines.push(`    description now: ${d.description.text === null ? '(none)' : quote(d.description.text)}`);
    }
    if (d.schema) {
      if (d.schema.unavailable) {
        if (d.schema.unavailable === 'approved') lines.push('    the approval recorded no parameters (it was made from hashes), so which ones changed is unknown');
        continue;
      }
      const s = d.schema;
      for (const p of s.params_added) lines.push(`    + param ${p.param} (${p.type}${p.required ? ', required' : ''})`);
      for (const p of s.params_removed) lines.push(`    - param ${p}`);
      for (const p of s.type_changed) lines.push(`    ~ param ${p.param}: ${p.from} → ${p.to}`);
      for (const p of s.required_added) lines.push(`    ~ param ${p} is now required`);
      for (const p of s.required_removed) lines.push(`    ~ param ${p} is no longer required`);
      if (!s.params_added.length && !s.params_removed.length && !s.type_changed.length
        && !s.required_added.length && !s.required_removed.length) {
        lines.push('    top-level parameters are unchanged; the difference is deeper (enum values, nested objects, or text inside the schema)');
      }
    }
  }
  return lines;
}

module.exports = {
  APPROVALS_KEY, HASHES_ONLY_NOTE, parseToolsFile, observeTools, observationFromSurface, schemaShape,
  pendingTools, hasPending, approvalFor, approve, describePending, describeLines, quote,
};
