'use strict';
/**
 * Which vault entry a configured server *is* — one answer for every command.
 *
 * A host config names a server whatever its author likes: `"pw"` for
 * `@playwright/mcp`, `"github"` for `github-mcp-server`. That key is a label.
 * What runs is the artifact the launch command resolves to, so the entry is
 * found by package identity — the launch read by lib/install_cmd.cjs
 * parseLaunch (via the canonical `install_cmd` lib/installed.cjs builds) and
 * keyed by lib/entry_model.cjs packageKey (ecosystem + package, PyPI names
 * normalised, the image for OCI). The config key never selects an entry, in
 * either direction: a server keyed `mcp-server-aws` that runs
 * `node ./innocent.js` is not the AWS entry, and one keyed `fetch` that runs
 * the AWS package is.
 *
 * The version is compared separately, because what the vault stored about
 * `x@1.0.0` is not a statement about `x@2.0.0`:
 *
 *   same       the launch pins the artifact the entry pins — the entry's hash
 *              and stored evidence are about these bytes
 *   different  the vault verified another version (or the launch resolves at
 *              start-up, so what runs is not knowable from here)
 *   unknown    one of the two sides does not name one artifact
 *
 * Before this module, `status` matched by package while `verify --installed`
 * / `--config` (and so `check`), `audit`, the budget, `lock`, `sbom` and the
 * org rules matched by the config key first: the same line was "in the vault"
 * for one command and "not in the vault DB" for the next.
 *
 * API:
 *   launchKey(installCmd)                  -> 'npm:pkg' | 'pypi:name' | 'oci:image' | 'git:src' | null
 *   matchLaunch(tools, installCmd)         -> { entry, package, installed_artifact, vault_artifact,
 *                                               version_match, pinned }
 *   entryForLaunch(tools, installCmd)      -> the entry, or null
 *   sameArtifactEntry(tools, installCmd)   -> the entry when version_match is 'same', else null
 */

const { toTypedEntry, artifactId, comparableArtifactId, packageKey, isExactArtifact } = require('./entry_model.cjs');
const { currentArtifactId } = require('./tiers.cjs');

function typedOf(tool) {
  try { return toTypedEntry(tool); } catch { return null; }
}

/** The package a launch command runs, without its version. */
function launchKey(installCmd) {
  if (typeof installCmd !== 'string' || !installCmd.trim()) return null;
  const t = typedOf({ install_cmd: installCmd });
  return t ? packageKey(t.artifact) : null;
}

// The entries that install `key`, in DB order. Not cached: a caller may edit
// its DB copy between two calls, and a hundred entries are cheap to read.
function entriesFor(tools, key) {
  return (Array.isArray(tools) ? tools : []).filter((tool) => {
    const t = typedOf(tool);
    return Boolean(t && packageKey(t.artifact) === key);
  });
}

/**
 * The entry a launch runs and how its version compares. With several entries
 * for one package (none today), the one pinning the launched artifact wins,
 * else the first in DB order — never the one whose name equals the config key.
 */
function matchLaunch(tools, installCmd) {
  const none = { entry: null, package: null, installed_artifact: null, vault_artifact: null, version_match: null, pinned: false };
  if (typeof installCmd !== 'string' || !installCmd.trim()) return none;
  const typed = typedOf({ install_cmd: installCmd });
  const key = typed ? packageKey(typed.artifact) : null;
  if (!key) return none;
  const candidates = entriesFor(tools, key);
  const comparable = comparableArtifactId(typed.artifact);
  const entry = candidates.find((t) => comparable && currentArtifactId(t) === comparable) || candidates[0] || null;
  const installedId = artifactId(typed.artifact);
  const pinned = isExactArtifact(typed.artifact);
  if (!entry) return { ...none, package: key, installed_artifact: installedId, pinned };
  const vaultId = currentArtifactId(entry);
  const vaultTyped = typedOf(entry);
  const vaultPinned = Boolean(vaultTyped && isExactArtifact(vaultTyped.artifact));
  // Equality is necessary and not sufficient: both sides must also *resolve*
  // to one artifact. `npx -y pkg` equals `npx -y pkg` and names nothing.
  const version_match = (!comparable || !vaultId) ? 'unknown'
    : (pinned && vaultPinned && comparable === vaultId ? 'same' : 'different');
  return { entry, package: key, installed_artifact: installedId, vault_artifact: vaultId, version_match, pinned };
}

const entryForLaunch = (tools, installCmd) => matchLaunch(tools, installCmd).entry;

function sameArtifactEntry(tools, installCmd) {
  const m = matchLaunch(tools, installCmd);
  return m.version_match === 'same' ? m.entry : null;
}

module.exports = { launchKey, matchLaunch, entryForLaunch, sameArtifactEntry };
