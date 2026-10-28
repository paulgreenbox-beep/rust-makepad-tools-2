import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {
  beginRun,
  digest,
  finishRun,
  loadProject,
  planProject,
  recordProject,
  validatePlan,
  verifyEvidence,
} from '../core/index.mjs';

const SIDECAR_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SIDECAR_ROOT, '..', '..');
const PROFILE_ROOT = path.join(REPO_ROOT, 'verification-economy', 'profiles', 'makepad-windows');
const FIXTURE_ROOT = path.join(os.tmpdir(), 'makepad-core-identity-capture-tests');

export const SYNTHETIC_VALIDATOR_FIXTURE = Object.freeze({
  marker: 'SYNTHETIC_VALIDATOR_FIXTURE',
  real_hardware_acceptance: false,
  application_launched: false,
  evidence_note: 'All reports, runtime identities, captures, and readbacks are fabricated Core contract fixtures.',
  schema_evidence_origin: 'real',
  owner: 'synthetic-fixture-owner',
  SessionId: 'SYNTHETIC-SESSION-20261016-001',
  adapter_bytes: 'SYNTHETIC_VALIDATOR_FIXTURE adapter implementation bytes; never loaded or executed.',
});

const RESOURCES = {
  desktop_lease: true,
  physical_input: true,
  native_clipboard: true,
  wslc_session: true,
  gpu: true,
  large_build: true,
  worker_lease: true,
  available_ram_mib: 4096,
  heavy_workloads_active: 0,
};

const json = value => `${JSON.stringify(value, null, 2)}\n`;
const parse = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const within = (root, ref) => path.resolve(root, ref);

function makeFixture(label) {
  fs.mkdirSync(FIXTURE_ROOT, {recursive: true});
  // Retain each fixture root as evidence. No fixture cleanup or recursive delete is performed.
  const root = fs.mkdtempSync(path.join(FIXTURE_ROOT, 'SYNTHETIC_VALIDATOR_FIXTURE-'));
  const write = (ref, value) => {
    const file = within(root, ref);
    fs.mkdirSync(path.dirname(file), {recursive: true});
    fs.writeFileSync(file, typeof value === 'string' ? value : json(value));
    return file;
  };
  const hash = ref => digest(fs.readFileSync(within(root, ref)));
  const sourceRecipe = ref => parse(path.join(PROFILE_ROOT, ref));

  write('SYNTHETIC_VALIDATOR_FIXTURE.json', {
    ...SYNTHETIC_VALIDATOR_FIXTURE,
    case: label,
    application_bytes_are_executable: false,
  });
  write('bin/synthetic-app.exe', 'SYNTHETIC_VALIDATOR_FIXTURE executable placeholder; never launched.');
  write('src/adapter.mjs', SYNTHETIC_VALIDATOR_FIXTURE.adapter_bytes);
  write('src/owned-contract.mjs', 'SYNTHETIC_VALIDATOR_FIXTURE trusted contract source bytes.');

  const rawPolicy = parse(path.join(PROFILE_ROOT, 'verification', 'verification-policy.json'));
  const binding = parse(path.join(PROFILE_ROOT, 'verification', 'toolkit-core.json'));
  for (const scenario of rawPolicy.scenario_registry) {
    const recipe = sourceRecipe(scenario.file);
    recipe.name = `SYNTHETIC_VALIDATOR_FIXTURE:${scenario.id}`;
    recipe.application.command = within(root, 'bin/synthetic-app.exe');
    const steps = [...(recipe.setup ?? []), ...recipe.steps, ...(recipe.teardown ?? [])];
    const contracts = steps.map((step, index) => {
      const isClose = step.op === 'session.close';
      return {
        index,
        operation: step.op,
        expected_state: {
          owner: SYNTHETIC_VALIDATOR_FIXTURE.owner,
          SessionId: SYNTHETIC_VALIDATOR_FIXTURE.SessionId,
          operation: step.op,
          revocation_state: isClose ? 'revoked' : 'active',
          lifetime_state: isClose ? 'ended' : 'live',
        },
      };
    });
    scenario.postcondition_contracts = contracts;
    recipe.postcondition_contracts = contracts;
    write(scenario.file, recipe);
  }
  write('verification/toolkit-core.json', binding);
  write('verification/verification-policy.json', rawPolicy);
  write('source-freeze.json', [
    {path: 'src/adapter.mjs', sha256: hash('src/adapter.mjs')},
    {path: 'src/owned-contract.mjs', sha256: hash('src/owned-contract.mjs')},
  ]);

  const policy = loadProject(root);
  const plan = planProject(policy, {
    milestone_id: `SYNTHETIC-${label}`,
    changed_modules: ['windows-ui'],
    artifact: {path: 'bin/synthetic-app.exe', sha256: hash('bin/synthetic-app.exe')},
    available_resources: RESOURCES,
  });
  assert.equal(plan.status, 'PLANNED', 'synthetic fixture must produce an executable Core plan');

  write('quality.json', {
    artifact: {sha256: hash('bin/synthetic-app.exe')},
    source_freeze_sha256: hash('source-freeze.json'),
    completed_at: '2026-10-16T00:00:00.000Z',
    gates: ['L0', 'L1', 'L2'].flatMap(level => plan.required[level]).map(gate => ({id: gate.id, exit_code: 0})),
    synthetic_fixture_only: true,
  });

  const proofs = [];
  for (const id of plan.selected_scenario_ids) {
    const scenario = policy.scenario_registry.find(item => item.id === id);
    const recipe = parse(within(root, scenario.file));
    const steps = [...(recipe.setup ?? []), ...recipe.steps, ...(recipe.teardown ?? [])];
    const run = beginRun(root, policy, plan, id, 'source-freeze.json');
    const reportFile = `evidence/${id}.json`;
    const observationFile = `evidence/${id}-observations.json`;
    const runFile = `evidence/${id}-run.json`;
    const captureFile = `evidence/${id}-synthetic-capture.bin`;
    write(captureFile, `SYNTHETIC_VALIDATOR_FIXTURE capture bytes for ${id}; not a screen capture.`);

    const reportSteps = steps.map((step, index) => {
      const mainStepCount = (recipe.setup ?? []).length + recipe.steps.length;
      const labelText = step.step_id ?? (index < mainStepCount ? `step-${index}` : `teardown-${index - mainStepCount}`);
      const result = step.op === 'get_runtime_health'
        ? {healthy: true, process_alive: true}
        : step.op === 'get_runtime_stderr' ? [] : true;
      return {
        index,
        step: labelText,
        operation: step.op,
        status: 'PASS',
        response: {success: true, result},
      };
    });
    const report = {
      test: recipe.name,
      status: 'PASSED',
      summary: {passed: steps.length, total: steps.length, failed: 0, skipped: 0},
      steps: reportSteps,
      synthetic_fixture_only: true,
      hardware_acceptance: false,
    };

    const observation = {
      schema_version: 2,
      evidence_origin: 'real',
      synthetic_fixture_only: true,
      producer_kind: 'native-runtime-observer',
      project_id: policy.project_id,
      scenario_id: id,
      run_id: run.run_id,
      plan_digest: plan.plan_digest,
      runtime: {
        pid: 12345,
        namespace: 'SYNTHETIC_VALIDATOR_FIXTURE',
        platform: 'synthetic',
        window_id: 'synthetic-window-identity',
        artifact_sha256: hash('bin/synthetic-app.exe'),
        started_at: run.started_at,
        owner: SYNTHETIC_VALIDATOR_FIXTURE.owner,
        SessionId: SYNTHETIC_VALIDATOR_FIXTURE.SessionId,
      },
      health: {
        healthy: true,
        process_alive: true,
        observed_pid: 12345,
        observation_source: 'synthetic-health-readback',
      },
      available_resources: RESOURCES,
      steps: [],
      capture: {
        evidence_path: captureFile,
        evidence_sha256: hash(captureFile),
        captured_at: run.started_at,
        owner: SYNTHETIC_VALIDATOR_FIXTURE.owner,
        SessionId: SYNTHETIC_VALIDATOR_FIXTURE.SessionId,
        synthetic_fixture_only: true,
      },
      cleanup: {
        pointer_buttons_released: true,
        modifiers_released: true,
        input_leases_released: true,
        processes_exited: true,
        windows_closed: true,
        worker_resources_released: true,
      },
    };

    for (let index = 0; index < steps.length; index++) {
      const step = steps[index];
      const correlation = `${run.run_id}:${index}`;
      const evidenceFile = `evidence/${id}-${index}-postcondition.json`;
      const contract = recipe.postcondition_contracts.find(item => item.index === index);
      write(evidenceFile, {
        evidence_origin: 'real',
        synthetic_fixture_only: true,
        run_id: run.run_id,
        correlation_id: correlation,
        operation: step.op,
        observation_source: 'synthetic-state-readback',
        actual_state: contract.expected_state,
        expected_state: contract.expected_state,
      });
      observation.steps.push({
        index,
        operation: step.op,
        correlation_id: correlation,
        action_dispatched: true,
        postcondition_verified: true,
        observation_source: 'synthetic-state-readback',
        dispatched_at: run.started_at,
        observed_at: run.started_at,
        evidence_path: evidenceFile,
        evidence_sha256: hash(evidenceFile),
        owner: SYNTHETIC_VALIDATOR_FIXTURE.owner,
        SessionId: SYNTHETIC_VALIDATOR_FIXTURE.SessionId,
      });
    }

    const cleanupFile = `evidence/${id}-cleanup.json`;
    write(cleanupFile, {
      evidence_origin: 'real',
      synthetic_fixture_only: true,
      run_id: run.run_id,
      orphan_processes: 0,
      stuck_pointer_buttons: 0,
      stuck_modifiers: 0,
      active_input_leases: 0,
      stale_windows: 0,
      leaked_resources: 0,
    });
    observation.cleanup.evidence_path = cleanupFile;
    observation.cleanup.evidence_sha256 = hash(cleanupFile);
    write(reportFile, report);
    write(observationFile, observation);
    const observedAt = new Date(Math.max(Date.now(), Date.parse(run.started_at) + 5));
    fs.utimesSync(within(root, reportFile), observedAt, observedAt);
    fs.utimesSync(within(root, observationFile), observedAt, observedAt);
    write(runFile, finishRun(root, run, reportFile, observationFile));
    proofs.push({id, status: 'PASS', artifact_hash: hash('bin/synthetic-app.exe'), report: reportFile, run_manifest: runFile});
  }

  const event = {
    project_id: policy.project_id,
    evidence_version: 2,
    milestone: plan.milestone,
    status: 'ACCEPTED',
    kind: 'functional',
    expanded_gui: plan.l4b_required,
    artifact_hash: hash('bin/synthetic-app.exe'),
    artifact_path: 'bin/synthetic-app.exe',
    quality_report: 'quality.json',
    source_freeze: 'source-freeze.json',
    date: '2026-10-16',
    scenario_results: proofs,
    synthetic_fixture_only: true,
    hardware_acceptance: false,
  };

  const readRunAndObservation = proof => {
    const run = parse(within(root, proof.run_manifest));
    return {run, observation: parse(within(root, run.observation_path))};
  };
  const persistObservation = (proof, run, observation) => {
    write(run.observation_path, observation);
    run.observation_sha256 = hash(run.observation_path);
    write(proof.run_manifest, run);
  };
  const mutateObservation = (mutate, proof = proofs[0]) => {
    const {run, observation} = readRunAndObservation(proof);
    mutate(observation);
    persistObservation(proof, run, observation);
  };
  const mutatePostcondition = (operation, mutate, proof = proofs[0]) => {
    const {run, observation} = readRunAndObservation(proof);
    const index = observation.steps.findIndex(step => step.operation === operation);
    assert.notEqual(index, -1, `synthetic recipe lacks ${operation}`);
    const step = observation.steps[index];
    const state = parse(within(root, step.evidence_path));
    mutate(state.actual_state);
    write(step.evidence_path, state);
    step.evidence_sha256 = hash(step.evidence_path);
    persistObservation(proof, run, observation);
  };

  return {root, policy, plan, event, proofs, write, hash, mutateObservation, mutatePostcondition};
}

test('explicit synthetic fixture verifies Core v2 shape without hardware acceptance', () => {
  const fixture = makeFixture('baseline');
  assert.equal(parse(within(fixture.root, 'SYNTHETIC_VALIDATOR_FIXTURE.json')).real_hardware_acceptance, false);
  assert.equal(verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan).verified_proof, true);
});

test('trusted postcondition denies a wrong owner readback', () => {
  const fixture = makeFixture('wrong-owner-readback');
  fixture.mutatePostcondition('get_runtime_health', state => { state.owner = 'foreign-owner'; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /trusted recipe\/consumer contract/,
  );
});

test('runtime owner identity mismatch is denied', () => {
  const fixture = makeFixture('wrong-runtime-owner');
  fixture.mutateObservation(observation => { observation.runtime.owner = 'foreign-owner'; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /runtime owner identity mismatch/,
  );
});

test('trusted postcondition denies a foreign SessionId readback', () => {
  const fixture = makeFixture('foreign-session-readback');
  fixture.mutatePostcondition('get_runtime_health', state => { state.SessionId = 'FOREIGN-SESSION'; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /trusted recipe\/consumer contract/,
  );
});

test('runtime step identity rejects a foreign SessionId', () => {
  const fixture = makeFixture('foreign-step-session');
  fixture.mutateObservation(observation => { observation.steps[0].SessionId = 'FOREIGN-SESSION'; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /runtime SessionId identity mismatch/,
  );
});

test('revocation contract rejects stale SessionId state at session close', () => {
  const fixture = makeFixture('stale-session-close-readback');
  fixture.mutatePostcondition('session.close', state => {
    state.SessionId = 'SYNTHETIC-STALE-SESSION';
    state.revocation_state = 'active';
    state.lifetime_state = 'live';
  });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /trusted recipe\/consumer contract/,
  );
});

test('stale process start predating the run is denied', () => {
  const fixture = makeFixture('stale-process');
  fixture.mutateObservation(observation => { observation.runtime.started_at = '2000-01-01T00:00:00.000Z'; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /runtime identity\/freshness missing/,
  );
});

test('wrong runtime binary hash is denied', () => {
  const fixture = makeFixture('wrong-binary-hash');
  fixture.mutateObservation(observation => { observation.runtime.artifact_sha256 = 'B'.repeat(64); });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /runtime identity\/freshness missing/,
  );
});

test('modified frozen adapter implementation bytes are denied', () => {
  const fixture = makeFixture('wrong-adapter-hash');
  fixture.write('src/adapter.mjs', 'SYNTHETIC_VALIDATOR_FIXTURE changed adapter implementation bytes.');
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /source changed after quality freeze/,
  );
});

test('modified plan is denied by the existing Core validator', () => {
  const fixture = makeFixture('modified-plan');
  const modifiedPlan = {...fixture.plan, plan_digest: '0'.repeat(64)};
  assert.throws(
    () => validatePlan(fixture.policy, modifiedPlan),
    /stale policy\/global binding or forged plan/,
  );
});

test('missing postcondition evidence is denied', () => {
  const fixture = makeFixture('missing-postcondition');
  fixture.mutateObservation(observation => { delete observation.steps[0].evidence_path; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /postcondition evidence missing or stale/,
  );
});

test('missing runtime identity is denied', () => {
  const fixture = makeFixture('missing-runtime-identity');
  fixture.mutateObservation(observation => { delete observation.runtime.pid; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /runtime identity\/freshness missing/,
  );
});

test('missing cleanup state is denied', () => {
  const fixture = makeFixture('missing-cleanup');
  fixture.mutateObservation(observation => { delete observation.cleanup.processes_exited; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /cleanup missing: processes_exited/,
  );
});

test('old capture timestamp is denied', () => {
  const fixture = makeFixture('old-capture-time');
  fixture.mutateObservation(observation => { observation.capture.captured_at = '2000-01-01T00:00:00.000Z'; });
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /capture timestamp is stale/,
  );
});

test('capture bytes that disagree with the recorded hash are denied', () => {
  const fixture = makeFixture('old-capture-bytes');
  const proof = fixture.proofs[0];
  const {run, observation} = (() => {
    const manifest = parse(within(fixture.root, proof.run_manifest));
    return {run: manifest, observation: parse(within(fixture.root, manifest.observation_path))};
  })();
  fixture.write(observation.capture.evidence_path, 'SYNTHETIC_VALIDATOR_FIXTURE stale capture bytes.');
  fixture.mutateObservation(value => { value.capture.captured_at = '2000-01-01T00:00:00.000Z'; }, proof);
  // Keep the recorded digest unchanged: a capture-aware verifier must detect these bytes.
  assert.notEqual(fixture.hash(observation.capture.evidence_path), observation.capture.evidence_sha256);
  assert.equal(observation.capture.evidence_sha256, parse(within(fixture.root, run.observation_path)).capture.evidence_sha256);
  assert.throws(
    () => verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan),
    /capture hash mismatch/,
  );
});

test('recordProject preserves exact replay idempotency and rejects a conflicting duplicate', () => {
  const fixture = makeFixture('record-replay-conflict');
  assert.equal(verifyEvidence(fixture.root, fixture.policy, fixture.event, fixture.plan).verified_proof, true);
  assert.equal(recordProject(fixture.root, fixture.event, fixture.plan).changed, true);
  const policyFile = within(fixture.root, 'verification/verification-policy.json');
  const afterFirstRecord = fs.readFileSync(policyFile, 'utf8');
  assert.equal(recordProject(fixture.root, fixture.event, fixture.plan).changed, false);
  assert.equal(fs.readFileSync(policyFile, 'utf8'), afterFirstRecord);
  assert.throws(
    () => recordProject(fixture.root, {...fixture.event, date: '2026-10-17'}, fixture.plan),
    /conflicting duplicate acceptance/,
  );
});
