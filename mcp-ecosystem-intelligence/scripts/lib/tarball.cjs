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
 *   readTarGz(buffer, opts)  -> { ok, files: [{ path, size, text }], truncated, skipped }
 *   parseTar(buffer, opts)   -> same, for an already-decompressed archive
 */

const zlib = require('zlib');

const BLOCK = 512;

/** An octal numeric field, tolerating the space/NUL padding tar uses. */
function octal(buf, offset, length) {
  const raw = buf.slice(offset, offset + length).toString('latin1').replace(/\0.*$/, '').trim();
  if (!raw) return 0;
  // GNU base-256 encoding for large values: high bit set on the first byte.
  if (buf[offset] & 0x80) {
    let value = 0;
    for (let i = offset; i < offset + length; i++) value = value * 256 + (buf[i] & (i === offset ? 0x7f : 0xff));
    return value;
  }
  const n = parseInt(raw, 8);
  return Number.isFinite(n) ? n : 0;
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
  // Set by an 'L' or 'x' header for the *next* entry only.
  let pendingName = null;

  while (offset + BLOCK <= buf.length) {
    const header = buf.slice(offset, offset + BLOCK);
    // Two consecutive zero blocks end the archive; one is enough to stop on.
    if (header.every((b) => b === 0)) break;

    const size     = octal(header, 124, 12);
    const typeflag = String.fromCharCode(header[156] || 0x30);
    const prefix   = cstring(header, 345, 155);
    const nameRaw  = cstring(header, 0, 100);
    const name     = pendingName || (prefix ? `${prefix}/${nameRaw}` : nameRaw);
    pendingName = null;

    const dataStart = offset + BLOCK;
    const dataEnd   = dataStart + size;
    // A size that runs past the buffer means a truncated or hostile archive.
    if (dataEnd > buf.length) { truncated = true; break; }
    const padded = Math.ceil(size / BLOCK) * BLOCK;

    if (typeflag === 'L') {
      // GNU long name: the payload is the name of the entry that follows.
      pendingName = buf.slice(dataStart, dataEnd).toString('utf8').replace(/\0+$/, '');
    } else if (typeflag === 'x' || typeflag === 'X') {
      // pax extended header: "<len> key=value\n" records. Only `path` matters.
      const text = buf.slice(dataStart, dataEnd).toString('utf8');
      const m = text.match(/\d+ path=([^\n]+)\n/);
      if (m) pendingName = m[1];
    } else if (typeflag === '0' || typeflag === '\0' || header[156] === 0) {
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
      // caller can say what it did not look at.
      skipped.entries++;
      skipped.byType[typeflag] = (skipped.byType[typeflag] || 0) + 1;
    }

    offset = dataStart + padded;
  }

  return { ok: true, files, truncated, skipped, bytesRead: kept };
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

module.exports = { readTarGz, parseTar, octal, cstring, BLOCK };
