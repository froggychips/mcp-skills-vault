#!/usr/bin/env node
/**
 * Is anybody using this?
 *
 * The honest answer has to be measured, and it has to be measured again later,
 * because "N downloads a month" is the kind of number that gets written into a
 * document once and then quoted for a year. This is a repo chore, not part of
 * the published CLI — it does not ship in the npm package.
 *
 * It reports four things and refuses to average them into a score:
 *
 *   npm downloads      how many times the tarball was fetched — by anyone,
 *                      including mirrors, CI and crawlers
 *   repo signals       stars, forks, watchers, issues opened by other people
 *   traffic            views and clones, with uniques
 *   the ratio          clones vs views, which is the tell: a human views
 *                      before cloning, so clones far above views means
 *                      automation, not adoption
 *
 * This tool has no telemetry and never will (docs/COMPATIBILITY.md), so none
 * of this can tell you whether anyone *ran* it, let alone whether it helped.
 * The only signal for that is a person saying so. That is the point of
 * docs/ADOPTION.md.
 *
 * Usage:
 *   node .github/scripts/adoption.cjs [--json]
 *
 * Needs `gh` authenticated for the repo half; the npm half needs no auth.
 */

'use strict';

const { execFileSync } = require('child_process');
const https = require('https');

const PKG  = '@froggychips/mcp-vault';
const REPO = 'froggychips/mcp-skills-vault';

function get(url) {
  return new Promise((resolve) => {
    const req = https.get(url, { timeout: 15000 }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        if (res.statusCode !== 200) return resolve({ ok: false, error: `HTTP ${res.statusCode}` });
        try { resolve({ ok: true, data: JSON.parse(body) }); }
        catch (e) { resolve({ ok: false, error: e.message }); }
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
  });
}

function gh(endpoint) {
  try {
    return { ok: true, data: JSON.parse(execFileSync('gh', ['api', endpoint], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })) };
  } catch (e) {
    // An endpoint we cannot read is not an endpoint that reported zero.
    return { ok: false, error: (e.stderr || e.message || '').toString().trim().slice(0, 120) };
  }
}

async function main() {
  const json = process.argv.includes('--json');

  const dl = await get(`https://api.npmjs.org/downloads/range/last-month/${encodeURIComponent(PKG)}`);
  const downloads = dl.ok
    ? {
        total: dl.data.downloads.reduce((n, d) => n + d.downloads, 0),
        days_with_any: dl.data.downloads.filter((d) => d.downloads > 0).length,
        days: dl.data.downloads.length,
        busiest: dl.data.downloads.reduce((m, d) => (d.downloads > m.downloads ? d : m), { downloads: 0 }),
        // Release days are when mirrors and registry scanners fetch every new
        // version. If three days carry most of the month, the month is mostly
        // them; the rest of the days are the background worth watching.
        top3: (() => {
          const days = [...dl.data.downloads].sort((a, b) => b.downloads - a.downloads).slice(0, 3);
          const sum = days.reduce((n, d) => n + d.downloads, 0);
          const total = dl.data.downloads.reduce((n, d) => n + d.downloads, 0);
          const rest = dl.data.downloads.filter((d) => !days.includes(d)).map((d) => d.downloads).sort((a, b) => a - b);
          return {
            days: days.map((d) => ({ day: d.day, downloads: d.downloads })),
            share: total ? Math.round((sum / total) * 100) : null,
            other_days: { count: rest.length, total: rest.reduce((n, x) => n + x, 0), median: rest.length ? rest[Math.floor(rest.length / 2)] : null },
          };
        })(),
        start: dl.data.start, end: dl.data.end,
      }
    : { error: dl.error };

  // Per-version downloads over the last week. Two versions fetched almost
  // equally right after they were published is a crawler pattern: a person
  // installs the latest one.
  const byVersion = await get(`https://api.npmjs.org/versions/${encodeURIComponent(PKG)}/last-week`);
  const versions = byVersion.ok ? byVersion.data.downloads : { error: byVersion.error };

  const repo      = gh(`repos/${REPO}`);
  const views     = gh(`repos/${REPO}/traffic/views`);
  const clones    = gh(`repos/${REPO}/traffic/clones`);
  const referrers = gh(`repos/${REPO}/traffic/popular/referrers`);
  const issues    = gh(`repos/${REPO}/issues?state=all&per_page=100`);

  // Issues and PRs opened by a *person* other than the repo owner: the
  // cheapest proof that a human found this and had something to say about it.
  //
  // Without the bot filter this list had 31 entries and looked like a busy
  // project. Every one was release-please, dependabot, the weekly refresh job
  // or Copilot — this repository's own automation talking to itself. That is
  // exactly the reading error the whole file exists to prevent, and it is the
  // same error as counting 41 clones as 41 interested readers.
  const owner = REPO.split('/')[0].toLowerCase();
  const isBot = (u) => !u || u.type === 'Bot' || /\[bot\]$/.test(u.login) || /^copilot$/i.test(u.login);
  const outside = issues.ok
    ? issues.data
        .filter((i) => !isBot(i.user) && (i.user.login || '').toLowerCase() !== owner)
        .map((i) => ({ number: i.number, title: i.title, author: i.user.login, pull_request: Boolean(i.pull_request) }))
    : null;
  const botOpened = issues.ok ? issues.data.filter((i) => isBot(i.user)).length : null;

  const report = {
    checked_at: new Date().toISOString(),
    npm: downloads,
    npm_versions_last_week: versions,
    repo: repo.ok
      ? { stars: repo.data.stargazers_count, forks: repo.data.forks_count, watchers: repo.data.subscribers_count }
      : { error: repo.error },
    traffic: {
      views:  views.ok  ? { total: views.data.count,  uniques: views.data.uniques }  : { error: views.error },
      clones: clones.ok ? { total: clones.data.count, uniques: clones.data.uniques } : { error: clones.error },
      referrers: referrers.ok ? referrers.data.map((r) => ({ from: r.referrer, uniques: r.uniques })) : { error: referrers.error },
    },
    outside_issues: outside,
    bot_opened_issues: botOpened,
    // Deliberately not a verdict. The one thing this data *can* rule out is
    // that the traffic is human: more clones than views means it is not.
    reading: (views.ok && clones.ok && clones.data.count > views.data.count)
      ? 'more clones than views — consistent with mirrors and crawlers, not with people'
      : null,
  };

  if (json) { process.stdout.write(`${JSON.stringify(report, null, 2)}\n`); return 0; }

  const w = (s) => process.stdout.write(`${s}\n`);
  w('');
  w(`npm            ${downloads.error ? `unavailable (${downloads.error})`
    : `${downloads.total} downloads ${downloads.start}…${downloads.end}, on ${downloads.days_with_any} of ${downloads.days} days (peak ${downloads.busiest.downloads})`}`);
  if (!downloads.error && downloads.top3.share !== null) {
    w(`               ${downloads.top3.share}% on three days (${downloads.top3.days.map((d) => `${d.day} ${d.downloads}`).join(', ')}); the other ${downloads.top3.other_days.count} days: ${downloads.top3.other_days.total} (median ${downloads.top3.other_days.median}/day)`);
  }
  w(`by version/7d  ${versions.error ? `unavailable (${versions.error})`
    : Object.entries(versions).sort((a, b) => b[1] - a[1]).map(([v, n]) => `${v} ${n}`).join(' · ')}`);
  w(`repo           ${repo.ok ? `${report.repo.stars} stars · ${report.repo.forks} forks · ${report.repo.watchers} watchers` : `unavailable (${repo.error})`}`);
  w(`traffic/14d    ${views.ok ? `${report.traffic.views.total} views (${report.traffic.views.uniques} unique)` : 'views unavailable'}`
    + ` · ${clones.ok ? `${report.traffic.clones.total} clones (${report.traffic.clones.uniques} unique)` : 'clones unavailable'}`);
  w(`referrers      ${referrers.ok ? (referrers.data.length ? referrers.data.map((r) => `${r.referrer} (${r.uniques})`).join(', ') : 'none') : 'unavailable'}`);
  w(`from people    ${outside === null ? 'unavailable' : (outside.length
    ? outside.map((i) => `#${i.number} ${i.author}: ${i.title}`).join('\n               ')
    : `none — 0 issues or PRs from a human other than the owner${botOpened ? ` (${botOpened} from this repo's own bots)` : ''}`)}`);
  if (report.reading) w(`\n${report.reading}`);
  w('\nNo telemetry, so none of this says whether anyone ran it. See docs/ADOPTION.md.\n');
  return 0;
}

main().then((code) => process.exit(code));
