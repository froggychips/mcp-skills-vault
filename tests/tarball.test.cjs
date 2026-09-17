'use strict';
/**
 * The tar reader.
 *
 * This parses attacker-supplied archives, so the tests are mostly about what it
 * refuses: an entry whose declared size runs past the end of the buffer, a
 * symlink, a decompression bomb. Nothing here writes to disk — the archive is
 * read in memory and entries come back as strings, which is the shortest path
 * to not having a path-traversal bug.
 *
 * Archives are built here rather than committed as fixtures, so the header
 * layout under test is visible in the test.
 */

const test   = require('node:test');
const assert = require('node:assert/strict');
const zlib   = require('zlib');

const t = require('../mcp-ecosystem-intelligence/scripts/lib/tarball.cjs');

const BLOCK = 512;

/** One ustar header + padded data. `type` is the typeflag character. */
function entry(name, data, { type = '0', prefix = '' } = {}) {
  const header = Buffer.alloc(BLOCK, 0);
  header.write(name, 0, 100, 'utf8');
  header.write('0000644\0', 100, 8, 'latin1');                     // mode
  header.write('0000000\0', 108, 8, 'latin1');                     // uid
  header.write('0000000\0', 116, 8, 'latin1');                     // gid
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'latin1');
  header.write('00000000000\0', 136, 12, 'latin1');                // mtime
  header.write('        ', 148, 8, 'latin1');                      // checksum placeholder
  header.write(type, 156, 1, 'latin1');
  header.write('ustar\0', 257, 6, 'latin1');
  header.write('00', 263, 2, 'latin1');
  if (prefix) header.write(prefix, 345, 155, 'utf8');
  // The checksum is the sum of the header bytes with the field itself spaces.
  let sum = 0;
  for (const b of header) sum += b;
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'latin1');

  const payload = Buffer.from(data);
  const padding = Buffer.alloc((BLOCK - (payload.length % BLOCK)) % BLOCK, 0);
  return Buffer.concat([header, payload, padding]);
}

const archive = (...entries) => Buffer.concat([...entries, Buffer.alloc(BLOCK * 2, 0)]);

test('reads regular files and their contents', () => {
  const tar = archive(
    entry('package/index.js', 'console.log("hi")\n'),
    entry('package/package.json', '{"name":"x"}'),
  );
  const r = t.parseTar(tar);
  assert.equal(r.ok, true);
  assert.deepEqual(r.files.map((f) => f.path), ['package/index.js', 'package/package.json']);
  assert.equal(r.files[0].text, 'console.log("hi")\n');
  assert.equal(r.files[0].size, 18);
});

test('a ustar prefix is joined to the name', () => {
  const tar = archive(entry('index.js', 'x', { prefix: 'deeply/nested/package' }));
  assert.equal(t.parseTar(tar).files[0].path, 'deeply/nested/package/index.js');
});

test('a GNU long name applies to the following entry only', () => {
  const longName = `package/${'a'.repeat(120)}/index.js`;
  const tar = archive(
    entry('././@LongLink', `${longName}\0`, { type: 'L' }),
    entry('package/truncated-name', 'body'),
    entry('package/second.js', 'second'),
  );
  const r = t.parseTar(tar);
  assert.deepEqual(r.files.map((f) => f.path), [longName, 'package/second.js']);
});

/** A pax record: the declared length counts the whole record, itself included. */
function paxRecord(key, value) {
  const body = ` ${key}=${value}\n`;
  // The length digits are part of the length, so solve for it.
  let len = body.length + 2;
  while (String(len).length + body.length !== len) len = String(len).length + body.length;
  return `${len}${body}`;
}

test('a pax extended header supplies the path', () => {
  const tar = archive(
    entry('PaxHeader/x', paxRecord('path', 'package/from-pax.js'), { type: 'x' }),
    entry('package/ignored', 'body'),
  );
  assert.equal(t.parseTar(tar).files[0].path, 'package/from-pax.js');
});

test('paxRecords walks declared lengths instead of searching the payload', () => {
  const records = t.paxRecords(paxRecord('path', 'a/b.js') + paxRecord('uid', '501'));
  assert.equal(records.get('path'), 'a/b.js');
  assert.equal(records.get('uid'), '501');
  // The attack: a value that *contains* a path record. Searching the blob for
  // `path=` took this as the next entry's name, so a .js file could be
  // presented under a name the include filter skips.
  const hostile = t.paxRecords(paxRecord('comment', '20 path=package/hidden.txt\n'));
  assert.equal(hostile.get('path'), undefined);
  assert.match(hostile.get('comment'), /path=package\/hidden\.txt/);
  // A declared length that does not fit stops the walk rather than guessing.
  assert.equal(t.paxRecords('99 path=x\n').size, 0);
});

test('a hostile pax comment cannot rename the next entry', () => {
  const tar = archive(
    entry('PaxHeader/x', paxRecord('comment', '20 path=package/hidden.txt\n'), { type: 'x' }),
    entry('package/real.js', 'code'),
  );
  const r = t.parseTar(tar, { include: (p) => p.endsWith('.js') });
  assert.deepEqual(r.files.map((f) => f.path), ['package/real.js']);
});

test('a long name survives a metadata header in between', () => {
  // GNU tar writes L → x → file. Clearing the pending name on the `x` made
  // this parser read the entry under its truncated 100-byte name while system
  // tar used the long one — enough to hide a .js file from an include filter.
  const longName = `package/${'d'.repeat(110)}/real.js`;
  const tar = archive(
    entry('././@LongLink', `${longName}\0`, { type: 'L' }),
    entry('PaxHeader/x', paxRecord('uid', '501'), { type: 'x' }),
    entry('package/fallback.txt', 'code'),
  );
  const r = t.parseTar(tar);
  assert.deepEqual(r.files.map((f) => f.path), [longName]);
});

test('a negative size stops the walk instead of looping forever', () => {
  // `parseInt('-0000001000', 8)` is -512: the bounds check passed, the padded
  // length went negative, and the offset moved *backwards* onto the same
  // header. An attacker-supplied archive that never terminates, in a parser
  // whose whole job is attacker-supplied archives.
  const header = entry('package/evil.js', 'x');
  header.write('-00000001000', 124, 12, 'latin1');
  const r = t.parseTar(Buffer.concat([header, Buffer.alloc(BLOCK * 3, 0)]), { include: () => false });
  assert.equal(r.truncated, true);
  assert.equal(r.files.length, 0);
});

test('a size field that is not octal is refused', () => {
  assert.equal(t.octal(Buffer.from('99999999999\0'), 0, 12), null);
  assert.equal(t.octal(Buffer.from('-0000001000\0'), 0, 12), null);
  assert.equal(t.octal(Buffer.from('0000000644\0 '), 0, 12), 0o644);
});

test('a name longer than the cap is refused rather than allocated', () => {
  const huge = 'p'.repeat(8000);
  const tar = archive(
    entry('././@LongLink', `${huge}\0`, { type: 'L' }),
    entry('package/x.js', 'code'),
  );
  const r = t.parseTar(tar, { maxBytes: 1 });
  assert.equal(r.truncated, true);
  // And the name budget is counted, not bypassed: the file is not returned
  // under maxBytes: 1 either.
  assert.equal(r.files.length, 0);
});

test('a short or non-tar payload is truncated, not an empty archive', () => {
  // The distinction this whole repo is about: "we read nothing" must not look
  // like "there was nothing to read".
  const short = t.parseTar(Buffer.from('not a tar at all'));
  assert.equal(short.truncated, true);
  assert.equal(short.endOfArchive, false);

  const proper = t.parseTar(archive(entry('package/a.js', 'x')));
  assert.equal(proper.truncated, false);
  assert.equal(proper.endOfArchive, true);
});

test('a dangling long name is truncated, not silently dropped', () => {
  const tar = archive(entry('././@LongLink', 'package/never-arrives.js\0', { type: 'L' }));
  const r = t.parseTar(tar);
  assert.equal(r.truncated, true);
  assert.equal(r.files.length, 0);
});

test('directories, symlinks and devices are skipped and counted', () => {
  const tar = archive(
    entry('package/', '', { type: '5' }),
    entry('package/link', 'target', { type: '2' }),
    entry('package/hard', 'target', { type: '1' }),
    entry('package/real.js', 'code'),
  );
  const r = t.parseTar(tar);
  assert.deepEqual(r.files.map((f) => f.path), ['package/real.js']);
  assert.equal(r.skipped.entries, 3);
  assert.deepEqual(Object.keys(r.skipped.byType).sort(), ['1', '2', '5']);
});

test('include() decides what is read, and the rest is not buffered', () => {
  const tar = archive(
    entry('package/index.js', 'code'),
    entry('package/fixture.bin', 'x'.repeat(4096)),
  );
  const r = t.parseTar(tar, { include: (p) => p.endsWith('.js') });
  assert.deepEqual(r.files.map((f) => f.path), ['package/index.js']);
  assert.equal(r.bytesRead, 4, 'the 4 KB fixture was never read into memory');
});

test('a size that runs past the buffer stops the walk instead of reading past it', () => {
  const header = entry('package/lying.js', 'short');
  // Claim 100 KB of payload for five bytes of data.
  header.write(`${(100000).toString(8).padStart(11, '0')}\0`, 124, 12, 'latin1');
  const r = t.parseTar(Buffer.concat([header, Buffer.alloc(BLOCK * 2, 0)]));
  assert.equal(r.truncated, true);
  assert.equal(r.files.length, 0);
});

test('maxBytes and maxFiles cap the read and say so', () => {
  const many = Array.from({ length: 10 }, (_, i) => entry(`package/f${i}.js`, 'x'.repeat(1000)));
  const capped = t.parseTar(archive(...many), { maxBytes: 2500 });
  assert.equal(capped.truncated, true);
  assert.equal(capped.files.length, 2);

  const fewer = t.parseTar(archive(...many), { maxFiles: 3 });
  assert.equal(fewer.files.length, 3);
  assert.equal(fewer.truncated, true);
});

test('readTarGz decompresses, and a bomb is an error rather than memory', () => {
  const tar = archive(entry('package/index.js', 'hello'));
  const gz = zlib.gzipSync(tar);
  const r = t.readTarGz(gz);
  assert.equal(r.ok, true);
  assert.equal(r.files[0].text, 'hello');

  // 4 MB of zeros compresses to a few KB; refuse it with a 1 KB ceiling.
  const bomb = zlib.gzipSync(Buffer.alloc(4 * 1024 * 1024, 0));
  const refused = t.readTarGz(bomb, { maxInflatedBytes: 1024 });
  assert.equal(refused.ok, false);
  assert.match(refused.error, /could not decompress/);
  assert.deepEqual(refused.files, []);
});

test('a corrupt gzip is an error, not an empty package', () => {
  const r = t.readTarGz(Buffer.from('not gzip at all'));
  assert.equal(r.ok, false);
  assert.deepEqual(r.files, []);
});

test('octal fields tolerate tar\'s padding, and GNU base-256 sizes', () => {
  const buf = Buffer.alloc(24, 0);
  buf.write('0000644\0', 0, 8, 'latin1');
  assert.equal(t.octal(buf, 0, 8), 0o644);
  buf.write('   755  ', 8, 8, 'latin1');
  assert.equal(t.octal(buf, 8, 8), 0o755);
  // Base-256: high bit set on the first byte, value in the remainder.
  const big = Buffer.alloc(12, 0);
  big[0] = 0x80;
  big[10] = 0x01;
  big[11] = 0x00;
  assert.equal(t.octal(big, 0, 12), 256);
});
