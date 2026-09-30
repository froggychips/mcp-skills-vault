'use strict';
/**
 * Preload for check_docker_drift CLI tests (`node -r`): no network, no real DB.
 *   DRIFT_STUB_DB       path to a fixture tools_database.json served instead of the real one
 *   DRIFT_STUB_DIGEST   what the "registry" returns as Docker-Content-Digest
 *   DRIFT_STUB_WRITTEN  where writeDb dumps the DB it was asked to write
 */
const fs   = require('fs');
const path = require('path');
const scripts = path.resolve(__dirname, '../../mcp-ecosystem-intelligence/scripts');

const oci = require(path.join(scripts, 'lib/oci.cjs'));
oci.fetchManifestDigest = async () => ({ digest: process.env.DRIFT_STUB_DIGEST });

const dbIo = require(path.join(scripts, 'lib/db_io.cjs'));
dbIo.writeDb = (_p, db) => fs.writeFileSync(process.env.DRIFT_STUB_WRITTEN, JSON.stringify(db));

const realRead = fs.readFileSync;
fs.readFileSync = function (p, ...rest) {
  if (typeof p === 'string' && p.endsWith(path.join('assets', 'tools_database.json'))) {
    return realRead.call(fs, process.env.DRIFT_STUB_DB, ...rest);
  }
  return realRead.call(fs, p, ...rest);
};
