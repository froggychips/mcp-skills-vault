#!/usr/bin/env node
/**
 * ci_health.cjs — deadman for a self-hosted-only CI, run from outside CI.
 *
 * Why this isn't a workflow: when the self-hosted runner goes offline, jobs
 * don't fail — they queue, get killed by the 24h limit, and land as
 * `cancelled`, which notifies nobody. That is how this repo's CI sat dead for
 * four weeks. The obvious fix is a watcher on a github-hosted runner, and it
 * exists (`.github/workflows/runner-health.yml`) — but this account has no
 * hosted minutes, so that job never starts. Until it does, the same two checks
 * run from the runner's own machine on a launchd timer.
 *
 * Known blind spot, stated rather than hidden: if the machine is off, nothing
 * checks. That case is self-evident to the operator; a removed runner
 * directory on a running machine — what actually happened twice — is not.
 *
 * Checks:
 *   1. A run has been queued longer than --queue-limit-min while no job
 *      anywhere is executing. Both halves matter: one runner takes one job at
 *      a time and a full security-scan runs for tens of minutes, so a backlog
 *      behind it is saturation, not death. Liveness is counted over *jobs* —
 *      a run keeps status `queued` while any of its jobs waits, even when
 *      another is mid-execution, so `runs?status=in_progress` reads zero
 *      during real work.
 *   2. No successful scheduled security-scan for --stale-limit-days.
 *
 * Runner status is deliberately not read: GET /actions/runners needs admin,
 * which neither GITHUB_TOKEN nor a default gh token carries. The symptom
 * checks also cover label mismatches and a wedged queue.
 *
 * Usage:
 *   ci_health.cjs --repo owner/name          repo to inspect (else gh's current)
 *   ci_health.cjs --queue-limit-min 30       queue age before it counts as stalled
 *   ci_health.cjs --stale-limit-days 8       weekly cron → 8 days allows one miss
 *   ci_health.cjs --workflow security-scan.yml
 *   ci_health.cjs --notify                   macOS notification on failure
 *   ci_health.cjs --json                     machine-readable verdict
 *
 * Requires the `gh` CLI, authenticated. Exit codes:
 *   0  healthy (or saturated — a warning, not a failure)
 *   1  a check failed
 *   2  bad arguments, or gh missing / not authenticated
 */

'use strict';

const { execFileSync } = require('child_process');

const DEFAULTS = {
  queueLimitMin:  30,
  staleLimitDays: 8,
  workflow:       'security-scan.yml',
};

function parseArgs(argv) {
  const opts = {
    repo: null, notify: false, json: false, help: false,
    queueLimitMin: DEFAULTS.queueLimitMin,
    staleLimitDays: DEFAULTS.staleLimitDays,
    workflow: DEFAULTS.workflow,
  };
  const int = (v, fallback) => {
    const n = parseInt(v, 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  };
  for (let i = 0; i < argv.length; i++) {
    const next = argv[i + 1];
    switch (argv[i]) {
      case '--repo':             opts.repo = next; i++; break;
      case '--queue-limit-min':  opts.queueLimitMin = int(next, DEFAULTS.queueLimitMin); i++; break;
      case '--stale-limit-days': opts.staleLimitDays = int(next, DEFAULTS.staleLimitDays); i++; break;
      case '--workflow':         opts.workflow = next; i++; break;
      case '--notify':           opts.notify = true; break;
      case '--json':             opts.json = true; break;
      case '-h':
      case '--help':             opts.help = true; break;
      default:
        if (argv[i].startsWith('--')) {
          process.stderr.write(`Unknown flag: ${argv[i]}\n`);
          opts.help = true;
        }
    }
  }
  return opts;
}

const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;

// Pure verdict, so the decision table is testable without a network or a repo.
// `lastSuccessMs === null` means "never succeeded", which is a failure rather
// than an unknown: a deadman that stays quiet because it found no history is
// the failure mode we're trying to eliminate.
function evaluate(state) {
  const {
    nowMs, queuedRuns = [], anyJobRunning = false, lastSuccessMs = null,
    queueLimitMin = DEFAULTS.queueLimitMin, staleLimitDays = DEFAULTS.staleLimitDays,
  } = state;

  const findings = [];

  const stalled = queuedRuns
    .map(r => ({ ...r, ageMin: Math.floor((nowMs - r.createdAtMs) / MIN) }))
    .filter(r => r.ageMin >= queueLimitMin);

  if (stalled.length === 0) {
    findings.push({ level: 'ok', check: 'queue', message: 'очередь чистая' });
  } else if (anyJobRunning) {
    findings.push({
      level: 'warn', check: 'queue',
      message: `${stalled.length} ран(ов) ждёт дольше ${queueLimitMin} мин, но джобы исполняются — сатурация, не падение`,
    });
  } else {
    const worst = Math.max(...stalled.map(r => r.ageMin));
    findings.push({
      level: 'fail', check: 'queue',
      message: `${stalled.length} ран(ов) ждёт до ${worst} мин и ни одна джоба не исполняется — раннер offline или лейблы не совпали`,
    });
  }

  if (lastSuccessMs === null) {
    findings.push({
      level: 'fail', check: 'staleness',
      message: 'ни одного успешного scheduled-рана в истории',
    });
  } else {
    const ageDays = Math.floor((nowMs - lastSuccessMs) / DAY);
    findings.push(ageDays >= staleLimitDays
      ? {
          level: 'fail', check: 'staleness',
          message: `нет успешного scheduled-рана ${ageDays} дн. (порог ${staleLimitDays}) — cron или раннер мёртв`,
        }
      : {
          level: 'ok', check: 'staleness',
          message: `последний успешный scheduled-ран ${ageDays} дн. назад`,
        });
  }

  const level = findings.some(f => f.level === 'fail') ? 'fail'
    : findings.some(f => f.level === 'warn') ? 'warn' : 'ok';
  return { level, findings };
}

// ── I/O ────────────────────────────────────────────────────────────────────

function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function ghJson(args) {
  return JSON.parse(gh(args));
}

function resolveRepo(opts) {
  if (opts.repo) return opts.repo;
  return ghJson(['repo', 'view', '--json', 'nameWithOwner']).nameWithOwner;
}

function fetchState(repo, opts) {
  const queued = ghJson(['api', `repos/${repo}/actions/runs?status=queued&per_page=100`]);
  const queuedRuns = (queued.workflow_runs || []).map(r => ({
    id: r.id, name: r.name, createdAtMs: Date.parse(r.created_at),
  }));

  // A job in `in_progress` always belongs to a run that is `queued` or
  // `in_progress`, so those two lists bound the search. Stop at the first hit.
  let anyJobRunning = false;
  outer:
  for (const status of ['in_progress', 'queued']) {
    const runs = ghJson(['api', `repos/${repo}/actions/runs?status=${status}&per_page=20`]);
    for (const run of runs.workflow_runs || []) {
      const jobs = ghJson(['api', `repos/${repo}/actions/runs/${run.id}/jobs`]);
      if ((jobs.jobs || []).some(j => j.status === 'in_progress')) {
        anyJobRunning = true;
        break outer;
      }
    }
  }

  const success = ghJson(['api',
    `repos/${repo}/actions/workflows/${opts.workflow}/runs?event=schedule&status=success&per_page=1`]);
  const last = (success.workflow_runs || [])[0];

  return {
    queuedRuns,
    anyJobRunning,
    lastSuccessMs: last ? Date.parse(last.updated_at) : null,
  };
}

function notify(title, message) {
  // Best-effort: a missing osascript must not turn a health report into a crash.
  try {
    execFileSync('osascript', [
      '-e',
      `display notification ${JSON.stringify(message)} with title ${JSON.stringify(title)}`,
    ], { stdio: 'ignore' });
  } catch { /* not macOS, or notifications unavailable */ }
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write('ci_health.cjs [--repo owner/name] [--queue-limit-min N] '
      + '[--stale-limit-days N] [--workflow f.yml] [--notify] [--json]\n');
    return 0;
  }

  let repo, state;
  try {
    gh(['auth', 'status']);
  } catch {
    process.stderr.write('gh CLI not found or not authenticated. Run: gh auth login\n');
    return 2;
  }
  try {
    repo  = resolveRepo(opts);
    state = fetchState(repo, opts);
  } catch (e) {
    // An unreachable API is itself worth shouting about — staying silent here
    // would recreate the blind spot this script exists to close.
    const msg = `не смог опросить GitHub API: ${(e.message || String(e)).split('\n')[0]}`;
    if (opts.json) process.stdout.write(JSON.stringify({ level: 'fail', findings: [{ level: 'fail', check: 'api', message: msg }] }, null, 2) + '\n');
    else process.stderr.write(`FAIL  ${msg}\n`);
    if (opts.notify) notify('CI health: опрос не удался', msg);
    return 1;
  }

  const verdict = evaluate({
    nowMs: Date.now(),
    ...state,
    queueLimitMin: opts.queueLimitMin,
    staleLimitDays: opts.staleLimitDays,
  });

  if (opts.json) {
    process.stdout.write(JSON.stringify({ repo, ...verdict }, null, 2) + '\n');
  } else {
    for (const f of verdict.findings) {
      const tag = f.level === 'fail' ? 'FAIL' : f.level === 'warn' ? 'WARN' : 'OK  ';
      process.stdout.write(`${tag}  [${f.check}] ${f.message}\n`);
    }
  }

  if (verdict.level === 'fail' && opts.notify) {
    notify(`CI health: ${repo}`, verdict.findings.filter(f => f.level === 'fail').map(f => f.message).join('; '));
  }
  return verdict.level === 'fail' ? 1 : 0;
}

if (require.main === module) process.exit(main());

module.exports = { evaluate, parseArgs, DEFAULTS };
