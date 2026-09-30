'use strict';
/**
 * A small JSON Schema (draft-07) validator, for tests only.
 *
 * The repo has no dependencies and a test suite is not a reason to start, so
 * this covers exactly the keywords the vendored server.schema.json uses —
 * `$ref` (local `#/definitions/…`), `type`, `required`, `properties`,
 * `additionalProperties`, `items`, `enum`, `const`, `pattern`, `minLength`,
 * `maxLength`, `anyOf`, `allOf`, `not`, and `format: uri` — and throws on any
 * other assertion keyword rather than silently passing it. A validator that
 * ignores what it does not know is how an invalid document passes.
 *
 *   validate(schema, value) -> [] | ['<path>: <message>', …]
 */

const KNOWN = new Set([
  '$ref', 'type', 'required', 'properties', 'additionalProperties', 'items',
  'enum', 'const', 'pattern', 'minLength', 'maxLength', 'anyOf', 'allOf', 'not', 'format',
  // annotations — no assertion
  '$schema', '$id', '$comment', 'title', 'description', 'default', 'example', 'examples', 'definitions',
]);

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}

function resolve(root, ref) {
  if (!ref.startsWith('#/')) throw new Error(`json_schema_lite: only local refs are supported, got ${ref}`);
  return ref.slice(2).split('/').reduce((node, key) => {
    const next = node && node[key.replace(/~1/g, '/').replace(/~0/g, '~')];
    if (next === undefined) throw new Error(`json_schema_lite: unresolvable $ref ${ref}`);
    return next;
  }, root);
}

function check(root, schema, value, at, errors) {
  if (schema === true) return;
  if (schema === false) { errors.push(`${at}: not allowed`); return; }
  for (const k of Object.keys(schema)) {
    if (!KNOWN.has(k)) throw new Error(`json_schema_lite: unsupported keyword "${k}" at ${at}`);
  }
  if (schema.$ref) check(root, resolve(root, schema.$ref), value, at, errors);

  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const t = typeOf(value);
    if (!types.includes(t) && !(t === 'integer' && types.includes('number'))) {
      errors.push(`${at}: expected ${types.join('|')}, got ${t}`);
      return;
    }
  }
  if (schema.enum && !schema.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) {
    errors.push(`${at}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  }
  if ('const' in schema && JSON.stringify(schema.const) !== JSON.stringify(value)) {
    errors.push(`${at}: must equal ${JSON.stringify(schema.const)}`);
  }
  if (typeof value === 'string') {
    if (schema.minLength != null && value.length < schema.minLength) errors.push(`${at}: shorter than ${schema.minLength}`);
    if (schema.maxLength != null && value.length > schema.maxLength) errors.push(`${at}: longer than ${schema.maxLength}`);
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) errors.push(`${at}: does not match ${schema.pattern}`);
    if (schema.format === 'uri') {
      try { new URL(value); } catch { errors.push(`${at}: not a URI`); }
    }
  }
  if (Array.isArray(value) && schema.items) {
    value.forEach((v, i) => check(root, schema.items, v, `${at}[${i}]`, errors));
  }
  if (typeOf(value) === 'object') {
    for (const r of schema.required || []) {
      if (!(r in value)) errors.push(`${at}: missing required "${r}"`);
    }
    const props = schema.properties || {};
    for (const [k, v] of Object.entries(value)) {
      if (k in props) check(root, props[k], v, `${at}.${k}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${at}: unexpected property "${k}"`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        check(root, schema.additionalProperties, v, `${at}.${k}`, errors);
      }
    }
  }
  if (schema.allOf) for (const s of schema.allOf) check(root, s, value, at, errors);
  if (schema.anyOf) {
    const ok = schema.anyOf.some((s) => { const e = []; check(root, s, value, at, e); return e.length === 0; });
    if (!ok) errors.push(`${at}: matches none of anyOf`);
  }
  if (schema.not) {
    const e = [];
    check(root, schema.not, value, at, e);
    if (e.length === 0) errors.push(`${at}: must not match the "not" schema`);
  }
}

function validate(schema, value) {
  const errors = [];
  check(schema, schema, value, '$', errors);
  return errors;
}

module.exports = { validate };
