'use strict';
/**
 * Read a .tgz without unpacking it to disk.
 *
 * Needed because the next question after "are these the bytes we verified" is
 * "what is *in* them", and answering that means reading the tarball. Nothing
 * here writes a file: the archive is decompressed in memory and the entries we
 * care about are returned as strings. An archive from npm is attacker-supplied
 * input, and the shortest path to not having a path-traversal bug is to never
 * have a path.
 *
 * zlib is in Node's standard library; tar is not, so the format is parsed here.
 * It is a simple format and this implementation covers what npm and PyPI
 * actually produce:
 *
 *   - ustar headers (512-byte blocks, octal numeric fields)
 *   - regular files (typeflag '0' or NUL) and directories ('5', skipped)
 *   - GNU long names ('L') and pax extended headers ('x'), both of which npm
 *     emits for deep paths
 *   - everything else (symlinks, hard links, device nodes, sparse files) is
 *     *skipped*, not guessed at. A symlink in a package we are reading for
 *     capabilities tells us nothing we can act on, and following one would be
 *     the bug.
 *
 * Limits are arguments rather than constants because the caller knows what it
 * is doing: a capability scan over 114 packages wants a tight per-archive cap,
 * and a one-off inspection does not.
 *
 * API:
 *   readTarGz(buffer, opts)  -> { ok, files, truncated, skipped, endOfArchive }
 *   parseTar(buffer, opts)   -> same, for an already-decompressed archive
 *   paxRecords(text)         -> Map   (pure)
 */

const zlib = require('zlib');

const BLOCK = 512;

/**
 * An octal numeric field, tolerating the space/NUL padding tar uses.
 *
 * Returns null for anything that is not a non-negative integer. That matters
 * for the size field specifically: `parseInt('-0000001000', 8)` is -512, which
 * passed the "runs past the buffer" check, made the padded length negative, and
 * moved the read offset *backwards* onto the same header — an attacker-supplied
 * archive that loops forever, in a tool whose job is to read attacker-supplied
 * archives.
 */
function octal(buf, offset, length) {
  const raw = buf.slice(offset, offset + length).toString('latin1').replace(/\0.*$/, '').trim();
  if (!raw) return 0;
  // GNU base-256 encoding for large values: high bit set on the first byte.
  if (buf[offset] & 0x80) {
    let value = 0;
    for (let i = offset; i < offset + length; i++) value = value * 256 + (buf[i] & (i === offset ? 0x7f : 0xff));
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  if (!/^[0-7]+$/.test(raw)) return null;
  const n = parseInt(raw, 8);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

/**
 * pax extended header records: `"<len> <key>=<value>\n"`, where `<len>` counts
 * the whole record including itself.
 *
 * Parsed by walking the lengths rather than searching the payload for
 * `path=`. A regex over the whole blob took the text inside *another* record's
 * value — a `comment=` containing "20 path=package/hidden.txt\n" — as the next
 * entry's name, which let an archive present a .js file under a name our
 * include filter would skip.
 */
function paxRecords(text) {
  const out = new Map();
  let i = 0;
  while (i < text.length) {
    const space = text.indexOf(' ', i);
    if (space === -1) break;
    const len = Number(text.slice(i, space));
    // A record must declare a length that keeps us inside the payload and
    // moves us forward; anything else is a malformed header, not a record.
    if (!Number.isSafeInteger(len) || len <= 0 || i + len > text.length) break;
    const record = text.slice(space + 1, i + len);
    const eq = record.indexOf('=');
    if (eq > 0) out.set(record.slice(0, eq), record.slice(eq + 1).replace(/\n$/, ''));
    i += len;
  }
  return out;
}

function cstring(buf, offset, length) {
  const slice = buf.slice(offset, offset + length);
  const end = slice.indexOf(0);
  return slice.slice(0, end === -1 ? slice.length : end).toString('utf8');
}

/**
 * Walk an uncompressed tar.
 *
 * `include(path)` decides what is kept as text; everything else is counted and
 * skipped. The point is to read a handful of .js files out of an archive that
 * may be 40 MB of fixtures.
 */
function parseTar(buf, { include = () => true, maxBytes = 8 * 1024 * 1024, maxFiles = 4000 } = {}) {
  const files = [];
  let offset = 0;
  let kept = 0;
  let truncated = false;
  const skipped = { entries: 0, byType: {} };
  // Set by an 'L' or 'x' header for the *next file* entry. Deliberately not
  // cleared by another metadata header in between: GNU tar writes
  // `L → x → file`, and clearing it there made this parser read the file under
  // its truncated 100-byte name while system tar used the long one — so a .js
  // file could be presented under a name the include filter skips.
  let pendingName = null;
  // A name is metadata, and metadata counts against the budget too: the first
  // version converted whole GNU/pax payloads to strings before checking
  // anything, so a 10 KB name arrived under `maxBytes: 1`.
  const MAX_NAME_BYTES = 4096;

  while (offset + BLOCK <= buf.length) {
    const header = buf.slice(offset, offset + BLOCK);
    // Two consecutive zero blocks end the archive; one is enough to stop on.
    if (header.every((b) => b === 0)) {
      // A pending long name with no entry to apply it to means the archive
      // stops mid-record. That is not a complete read.
      if (pendingName !== null) truncated = true;
      return { ok: true, files, truncated, skipped, bytesRead: kept, endOfArchive: true };
    }

    const size     = octal(header, 124, 12);
    const typeflag = String.fromCharCode(header[156] || 0x30);

    // A size that is not a size (negative, absurd, non-octal) makes every
    // subsequent offset meaningless. Stop rather than guess.
    if (size === null) {
      truncated = true;
      break;
    }

    const prefix   = cstring(header, 345, 155);
    const nameRaw  = cstring(header, 0, 100);

    const dataStart = offset + BLOCK;
    const dataEnd   = dataStart + size;
    // A size that runs past the buffer means a truncated or hostile archive.
    if (dataEnd > buf.length) { truncated = true; break; }
    const padded = Math.ceil(size / BLOCK) * BLOCK;

    if (typeflag === 'L') {
      // GNU long name: the payload is the name of the entry that follows.
      if (size > MAX_NAME_BYTES) {
        truncated = true;
      } else {
        kept += size;
        pendingName = buf.slice(dataStart, dataEnd).toString('utf8').replace(/\0+$/, '');
      }
    } else if (typeflag === 'x' || typeflag === 'X' || typeflag === 'g') {
      // pax extended header. Only `path` changes what we read; a `g` (global)
      // header's path applies to following entries, which we treat the same
      // way — the alternative is ignoring it and reading the wrong name.
      if (size > MAX_NAME_BYTES) {
        truncated = true;
      } else {
        kept += size;
        const records = paxRecords(buf.slice(dataStart, dataEnd).toString('utf8'));
        const paxPath = records.get('path');
        if (paxPath) pendingName = paxPath;
      }
    } else if (typeflag === '0' || typeflag === '\0' || header[156] === 0) {
      const name = pendingName || (prefix ? `${prefix}/${nameRaw}` : nameRaw);
      pendingName = null;
      if (files.length >= maxFiles) {
        truncated = true;
      } else if (include(name)) {
        if (kept + size > maxBytes) {
          truncated = true;
        } else {
          kept += size;
          files.push({ path: name, size, text: buf.slice(dataStart, dataEnd).toString('utf8') });
        }
      }
    } else {
      // Directories, symlinks, links, devices, and the rest. Counted so a
      // caller can say what it did not look at. A pending long name belonged
      // to this entry, so it is spent.
      pendingName = null;
      skipped.entries++;
      skipped.byType[typeflag] = (skipped.byType[typeflag] || 0) + 1;
    }

    const next = dataStart + padded;
    // Belt and braces: the offset must advance. With `size` validated above
    // this cannot trigger, and it is the invariant that turns any future
    // arithmetic mistake into a stop instead of a hang.
    if (next <= offset) { truncated = true; break; }
    offset = next;
  }

  // Falling out of the loop means we ran out of buffer without reaching the
  // end-of-archive blocks. Reporting `truncated: false` there made a ten-byte
  // non-tar payload indistinguishable from a successfully read empty archive.
  if (offset + BLOCK > buf.length && buf.length - offset !== 0) truncated = true;
  if (pendingName !== null) truncated = true;
  return { ok: true, files, truncated, skipped, bytesRead: kept, endOfArchive: false };
}

/** Decompress and walk. A gzip member that does not inflate is an error. */
function readTarGz(buffer, opts = {}) {
  let tar;
  try {
    tar = zlib.gunzipSync(buffer, { maxOutputLength: opts.maxInflatedBytes || 256 * 1024 * 1024 });
  } catch (e) {
    // A decompression bomb trips `maxOutputLength`, and a corrupt download
    // trips the checksum. Both are "we could not read this", and neither is
    // "there is nothing in it".
    return { ok: false, error: `could not decompress: ${e.message}`, files: [] };
  }
  return parseTar(tar, opts);
}

module.exports = { readTarGz, parseTar, octal, cstring, paxRecords, BLOCK };
