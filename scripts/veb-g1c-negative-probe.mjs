#!/usr/bin/env node
/**
 * Synthetic native-rule denial test for the dedicated PUBLIC G1c sandbox only.
 * Runs as GitHub Actions GITHUB_TOKEN. Never transmits or prints the token.
 * Writes only a synthetic canary to the protected main ref; a success is
 * classified as a critical boundary failure, not accepted as a passing test.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';

const expectedRepo = 'BlockSiFr/veb-g1c-public-veb-sandbox';
const expectedBranch = 'probe/g1c-native-negative-20261112';
const env = process.env;
const artifact = 'veb-native-negative-evidence.json';
const evidence = {
  schemaVersion: 'veb.g1c.native-negative.v1',
  repository: expectedRepo,
  branch: 'main',
  probeBranch: expectedBranch,
  runId: env.GITHUB_RUN_ID ?? null,
  observedAt: new Date().toISOString(),
  actorClass: 'GITHUB_ACTIONS_EPHEMERAL_TOKEN',
  provider: 'github',
  repoId: null,
  protectedHeadSha: null,
  ruleId: 27138828,
  ruleFingerprint: null,
  bypassActorListVisibleToProbe: null,
  actorWritePermission: null,
  actorAdminPermission: null,
  actorMaintainPermission: null,
  unprotectedWriteControl: {
    status: null,
    providerRequestId: null,
    providerCommitSha: null,
  },
  providerStatus: null,
  providerRequestId: null,
  ruleDenialAttributed: false,
  evidenceState: 'NOT_TESTED',
  certificationEligible: false,
  limitations: ['Synthetic sandbox only', 'One GitHub Contents API path only',
    'No broker-authorized positive comparison', 'No provider audit reconciliation',
    'Bypass actor inventory independently reviewed with repository administrator access; non-admin view may omit it'],
};
function save() {
  fs.writeFileSync(artifact, JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
  if (env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(env.GITHUB_STEP_SUMMARY,
      '### BlockSiFr G1c native negative test\n' +
      'State: **' + evidence.evidenceState + '**\n\n' +
      'HTTP: ' + (evidence.providerStatus ?? 'not attempted') + '\n\n' +
      'Native request ID: ' + (evidence.providerRequestId ?? 'not available') + '\n\n' +
      'This is not an enforcement certificate.\n');
  }
}
const expectedOwner = 'blocksifr';
const expectedName = 'veb-g1c-public-veb-sandbox';
const apiBase = 'https://api.github.com/repos/BlockSiFr/veb-g1c-public-veb-sandbox';

async function api(route, init = {}) {
  const res = await fetch(route.startsWith('https://') ? route : apiBase + route, {
    ...init,
    headers: {
      authorization: 'Bearer ' + env.GITHUB_TOKEN,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'blocksifr-veb-native-synthetic-test',
      ...(init.headers ?? {}),
    },
    signal: AbortSignal.timeout(20000),
  });
  let body;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body, requestId: res.headers.get('x-github-request-id') };
}
function requireTest(check, reason) {
  if (!check) throw Error(reason);
}

try {
  requireTest(env.GITHUB_REPOSITORY?.toLowerCase() === expectedRepo.toLowerCase(),
    'Wrong repository');
  requireTest(env.GITHUB_REF_NAME === expectedBranch, 'Wrong workflow branch');
  requireTest(env.GITHUB_EVENT_NAME === 'push', 'Only a trusted push event is supported');
  requireTest(typeof env.GITHUB_TOKEN === 'string' && env.GITHUB_TOKEN.length > 0,
    'Missing ephemeral GitHub Actions token');

  const repo = await api('');
  requireTest(repo.status === 200, 'Repository metadata unavailable');
  requireTest(repo.body?.owner?.login?.toLowerCase() === expectedOwner
      && repo.body?.name === expectedName
      && repo.body?.full_name?.toLowerCase() === expectedRepo.toLowerCase()
      && repo.body?.private === false
      && repo.body?.default_branch === 'main', 'Unexpected repository identity or visibility');
  evidence.repoId = repo.body.id;

  const perms = repo.body?.permissions ?? {};
  evidence.actorWritePermission = perms.push === true;
  evidence.actorAdminPermission = perms.admin === true;
  evidence.actorMaintainPermission = perms.maintain === true;
  // GitHub App installation tokens can report permissions.push=false even when
  // the Contents:write permission is effective. Prove actual write capability
  // using a synthetic canary on the unprotected probe branch instead.
  requireTest(evidence.actorAdminPermission === false && evidence.actorMaintainPermission === false,
    'Probe token must not have repository admin or maintainer permission');

  const [ruleset, branch, active] = await Promise.all([
    api('/rulesets/27138828'), api('/branches/main'), api('/rules/branches/main?per_page=100'),
  ]);
  console.log('Native rules read-only status: ruleset=' + ruleset.status +
    ', branch=' + branch.status + ', applicable=' + active.status +
    ', active=' + (ruleset.body?.enforcement ?? 'unavailable') +
    ', bypassActors=' + (Array.isArray(ruleset.body?.bypass_actors) ? ruleset.body.bypass_actors.length : 'unavailable') +
    ', ruleTypes=' + (Array.isArray(ruleset.body?.rules) ? ruleset.body.rules.map(r=>r.type).join(',') : 'unavailable'));
  evidence.bypassActorListVisibleToProbe = Array.isArray(ruleset.body?.bypass_actors);
  // GitHub omits bypass_actors for a Contents:write non-admin caller. Reject
  // a nonempty visible list; independently corroborate the hidden list via
  // an administrator read, never assume an omitted list means "no bypass".
  const noVisibleBypass = !Array.isArray(ruleset.body?.bypass_actors)
    || ruleset.body.bypass_actors.length === 0;
  requireTest(ruleset.status === 200 && ruleset.body?.enforcement === 'active'
    && ruleset.body?.target === 'branch'
    && noVisibleBypass
    && JSON.stringify(ruleset.body.conditions?.ref_name?.include) === JSON.stringify(['~DEFAULT_BRANCH'])
    && ruleset.body.rules?.some(r => r.type === 'update')
    && ruleset.body.rules?.some(r => r.type === 'deletion'),
    'Active no-bypass default-branch ruleset cannot be verified');
  requireTest(branch.status === 200 && branch.body?.protected === true &&
    /^[a-f0-9]{40}$/.test(branch.body?.commit?.sha ?? ''), 'Protected branch not verified');
  evidence.protectedHeadSha = branch.body.commit.sha;
  requireTest(active.status === 200 && Array.isArray(active.body)
    && active.body.length > 0 && active.body.length < 100
    && active.body.some(r => r.type === 'update')
    && active.body.some(r => r.type === 'deletion'),
    'Active applicable branch rules cannot be verified');

  const canonical = active.body.map(r => ({
    id: r.ruleset_id ?? null,
    source: r.ruleset_source_type ?? null,
    type: r.type,
    parameters: r.parameters ?? null,
  })).map(x => Object.fromEntries(Object.entries(x).sort(([a], [b]) => a.localeCompare(b))));
  canonical.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  evidence.ruleFingerprint = crypto.createHash('sha256')
    .update(JSON.stringify(canonical)).digest('hex');

  const controlPath = 'veb-probe/actions-positive-control-' + (env.GITHUB_RUN_ID ?? 'unknown') + '.txt';
  const control = await api('/contents/' + controlPath, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      message: 'test(veb): verify synthetic non-admin write authority on unprotected probe branch',
      content: Buffer.from('SYNTHETIC unprotected write positive control\\n').toString('base64'),
      branch: expectedBranch,
    }),
  });
  evidence.unprotectedWriteControl.status = control.status;
  evidence.unprotectedWriteControl.providerRequestId = control.requestId;
  evidence.unprotectedWriteControl.providerCommitSha = control.body?.commit?.sha ?? null;
  requireTest(control.status === 201 && Boolean(control.requestId) &&
    /^[a-f0-9]{40}$/.test(control.body?.commit?.sha ?? ''),
    'The ephemeral token could not complete the non-admin unprotected-branch write positive control');

  const path = 'veb-probe/actions-synthetic-' + (env.GITHUB_RUN_ID ?? 'unknown') + '.txt';
  const content = Buffer.from('SYNTHETIC BlockSiFr VEB G1c native rule probe\n').toString('base64');
  const result = await api('/contents/' + path, {
    method: 'PUT', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ message: 'test(veb): native guarded branch negative control', content, branch: 'main' }),
  });
  evidence.providerStatus = result.status;
  evidence.providerRequestId = result.requestId;
  const message = String(result.body?.message ?? '');
  evidence.ruleDenialAttributed =
    (result.status === 409
      && /repository rule violations found/i.test(message)
      && /cannot update this protected ref/i.test(message))
    || ((result.status === 403 || result.status === 422)
      && /(GH013|repository rule violations found)/i.test(message));
  evidence.ruleDenialAttributed &&= Boolean(result.requestId);
  if (result.status === 200 || result.status === 201) {
    evidence.evidenceState = 'CRITICAL_NATIVE_BYPASS';
    console.error('CRITICAL: Native write succeeded. The synthetic canary requires manual investigation.');
  } else if (evidence.ruleDenialAttributed) {
    evidence.evidenceState = 'NATIVE_NONADMIN_DIRECT_DENIAL_OBSERVED';
    console.log('PASS: Native GitHub restriction denied a write-capable, non-admin ephemeral actor.');
  } else {
    evidence.evidenceState = 'UNATTRIBUTED_DENIAL';
    console.error('FAIL: No attributable native rule denial. Ordinary authorization failure is insufficient.');
  }
} catch (err) {
  evidence.evidenceState = 'PREFLIGHT_FAILED';
  console.error('FAIL (no sensitive content): ' + String(err instanceof Error ? err.message : err).slice(0,240));
} finally {
  save();
}
if (evidence.evidenceState !== 'NATIVE_NONADMIN_DIRECT_DENIAL_OBSERVED') {
  process.exitCode = 1;
}
