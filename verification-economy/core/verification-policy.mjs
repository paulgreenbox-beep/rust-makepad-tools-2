// Extracted from RudraOffice; compatibility primitives, never executes apps/Cargo/GUI.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {validateGlobalOverlay, globalDigest} from './global-policy.mjs';
import {approvedHostArtifact} from './executable-provenance.mjs';

export const LEVELS = ['L0', 'L1', 'L2', 'L3', 'L4a', 'L4b', 'L5'];
export const STATUSES = ['NEW_CRITICAL', 'ROUTINE_GUI', 'PERIODIC_GUI', 'RISK_TRIGGERED', 'LOWER_LEVEL_ONLY', 'RETIRED'];
export const OUTCOMES = ['PASS', 'FAIL_PRODUCT', 'BLOCKED_ENVIRONMENT', 'FAIL_TEST_INFRA', 'NOT_RUN'];
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const unique = a => [...new Set(a)].sort();
const normalized = p => p.replaceAll('\\', '/');
const hash = v => crypto.createHash('sha256').update(typeof v === 'string' || Buffer.isBuffer(v) ? v : JSON.stringify(v)).digest('hex').toUpperCase();
const fail = message => {throw new Error(message);};
const assert = (condition, message) => {if (!condition) fail(message);};
const nonempty = v => typeof v === 'string' && v.trim().length > 0;
const integer = v => Number.isSafeInteger(v) && v >= 0;
const inside = (root, relative) => {
  assert(nonempty(relative) && !path.isAbsolute(relative) && !relative.split(/[\\/]/).includes('..'), `unsafe project reference: ${relative}`);
  const resolved = path.resolve(root, relative);
  assert(resolved.startsWith(path.resolve(root) + path.sep), `reference outside project: ${relative}`);
  return resolved;
};
export function readJson(file) {return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));}

export function validatePolicy(policy, root, {checkFiles = true} = {}) {
  assert(object(policy) && policy.schema_version === 1, 'unsupported policy schema_version');
  validateGlobalOverlay(policy);
  assert(/^\d+\.\d+\.\d+$/.test(policy.policy_version ?? ''), 'invalid policy_version');
  assert(object(policy.levels) && JSON.stringify(Object.keys(policy.levels).sort()) === JSON.stringify([...LEVELS].sort()), 'invalid verification levels');
  for (const level of LEVELS) assert(nonempty(policy.levels[level]?.title), `missing level ${level} title`);
  assert(Array.isArray(policy.risk_triggers) && policy.risk_triggers.length > 0, 'risk_triggers missing');
  const risks = policy.risk_triggers.map(r => r.id);
  assert(risks.every(nonempty) && unique(risks).length === risks.length, 'duplicate/missing risk trigger');
  const features = policy.feature_tags;
  assert(Array.isArray(features) && features.every(nonempty) && unique(features).length === features.length, 'invalid feature tags');
  const periodic = policy.periodic_regression;
  assert(object(periodic) && integer(periodic.interval) && periodic.interval > 0, 'invalid periodic interval');
  assert(['KNOWN', 'UNKNOWN_LEGACY_BASELINE'].includes(periodic.state), 'invalid periodic state');
  if (periodic.state === 'KNOWN') {
    assert(nonempty(periodic.last_full_gui_milestone) && integer(periodic.milestones_since_last_full), 'known counter missing baseline/count');
  } else {
    assert(periodic.last_full_gui_milestone === null && periodic.milestones_since_last_full === null, 'unknown legacy counter must not invent a baseline/count');
  }
  assert(nonempty(periodic.next_recommended_full), 'next_recommended_full missing');
  assert(Array.isArray(policy.milestone_history), 'milestone_history missing');
  const history = policy.milestone_history;
  assert(unique(history.map(h => h.milestone)).length === history.length, 'duplicate milestone history');
  for (const event of history) {
    assert(nonempty(event.milestone) && event.status === 'ACCEPTED' && event.kind === 'functional', 'history counts only accepted functional milestones');
    assert(/^[A-F0-9]{64}$/.test(event.artifact_hash ?? '') && nonempty(event.date), 'history artifact/date missing');
    assert(event.expanded_gui === true || event.expanded_gui === false || event.expanded_gui === null, 'invalid expanded history marker');
  }
  if (periodic.state === 'KNOWN') {
    const index = history.findIndex(h => h.milestone === periodic.last_full_gui_milestone && h.expanded_gui === true);
    assert(index >= 0 && history.length - index - 1 === periodic.milestones_since_last_full, 'counter disagrees with append-only accepted history');
  }
  const budgets = policy.budgets;
  for (const key of ['focused_new_feature_gui', 'routine_golden_gui', 'real_file_gui', 'frozen_artifact_smoke', 'typical_gui_runs']) {
    assert(integer(budgets?.[key]) && budgets[key] > 0, `invalid budget ${key}`);
  }
  assert(budgets.frozen_artifact_smoke === 1, 'frozen artifact smoke budget must be one');
  const tests = policy.test_registry;
  assert(Array.isArray(tests) && tests.length > 0 && unique(tests.map(t => t.id)).length === tests.length, 'duplicate/missing test id');
  for (const test of tests) assert(nonempty(test.owner) && ['L0', 'L1', 'L2'].includes(test.level) && nonempty(test.command) && nonempty(test.workdir), `invalid owned test ${test.id}`);
  const scenarios = policy.scenario_registry;
  assert(Array.isArray(scenarios) && scenarios.length > 0, 'scenario registry missing');
  const ids = scenarios.map(s => s.id);
  assert(ids.every(nonempty) && unique(ids).length === ids.length, 'duplicate scenario IDs');
  for (const scenario of scenarios) {
    assert(nonempty(scenario.owner), `missing owner ${scenario.id}`);
    assert(['L3', 'L4a', 'L4b', 'L5'].includes(scenario.level), `invalid scenario level ${scenario.id}`);
    assert(STATUSES.includes(scenario.status) && ['stable', 'flaky_candidate', 'quarantined'].includes(scenario.stability), `invalid lifecycle ${scenario.id}`);
    assert(['cheap', 'medium', 'expensive', 'very_expensive'].includes(scenario.cost), `invalid cost ${scenario.id}`);
    assert(object(scenario.cost_factors), `cost factors missing ${scenario.id}`);
    assert(Array.isArray(scenario.risk_tags) && scenario.risk_tags.every(r => risks.includes(r)), `unknown risk tag ${scenario.id}`);
    assert(Array.isArray(scenario.features_proven) && scenario.features_proven.every(f => features.includes(f)), `unknown feature ${scenario.id}`);
    assert(Array.isArray(scenario.lower_level_coverage) && scenario.lower_level_coverage.every(id => tests.some(t => t.id === id)), `unknown lower-level coverage ${scenario.id}`);
    assert(Array.isArray(scenario.run_when) && scenario.run_when.every(f => features.includes(f)) && typeof scenario.periodic === 'boolean', `missing/unknown run_when/periodic ${scenario.id}`);
    assert(nonempty(scenario.file), `missing scenario file ${scenario.id}`);
    if (checkFiles) {
      const file = inside(root, scenario.file);
      assert(fs.existsSync(file), `scenario does not exist ${scenario.id}`);
      const script = readJson(file);
      assert(script.version === 1 && Array.isArray(script.steps) && script.steps.length > 0 && object(script.application), `invalid public scenario recipe ${scenario.id}`);
      assert(script.teardown?.some(s => s.op === 'session.close'), `scenario lacks teardown ${scenario.id}`);
    }
    assert(scenario.last_passed_artifact === null || /^[A-F0-9]{64}$/.test(scenario.last_passed_artifact), `invalid last passed artifact ${scenario.id}`);
    assert(scenario.last_passed_date === null || nonempty(scenario.last_passed_date), `invalid last passed date ${scenario.id}`);
    assert((scenario.last_passed_artifact === null) === (scenario.last_passed_date === null), `incomplete last PASS identity ${scenario.id}`);
  }
  assert(Array.isArray(policy.golden_scenarios) && unique(policy.golden_scenarios).length === policy.golden_scenarios.length, 'invalid golden workflows');
  for (const id of policy.golden_scenarios) assert(scenarios.some(s => s.id === id && s.level === 'L4a'), `golden scenario missing ${id}`);
  for (const scenario of scenarios) {
    for (const id of scenario.subsumes ?? []) {
      const other = scenarios.find(s => s.id === id);
      assert(other && policy.golden_scenarios.includes(id), `unknown subsumed golden ${id}`);
      assert(other.features_proven.every(f => scenario.features_proven.includes(f)), `incomplete composition coverage ${scenario.id} -> ${id}`);
    }
  }
  assert(Array.isArray(policy.change_impact) && policy.change_impact.length > 0, 'change impact missing');
  for (const rule of policy.change_impact) {
    assert(nonempty(rule.id) && Array.isArray(rule.paths) && Array.isArray(rule.modules), 'invalid impact rule');
    assert(rule.tests.every(id => tests.some(t => t.id === id)), `unknown impact test ${rule.id}`);
    assert(rule.feature_tags.every(t => features.includes(t)) && rule.risk_triggers.every(t => risks.includes(t)), `invalid impact tags ${rule.id}`);
  }
  assert(object(policy.ownership_rules) && object(policy.lifecycle) && object(policy.retry_policy), 'ownership/lifecycle/retry policy missing');
  assert(policy.artifact_smoke?.level === 'L5' && policy.artifact_smoke.after_required_gui === true, 'unsafe artifact smoke prerequisites');
  assert(Array.isArray(policy.exceptions), 'exceptions missing');
  return {status: 'PASS', schema_version: policy.schema_version, scenarios: scenarios.length, golden: policy.golden_scenarios.length, tests: tests.length};
}

export function matches(pattern, file) {
  const regex = '^' + pattern.split('*').map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$';
  return new RegExp(regex, 'i').test(file);
}
export function planVerification(policy, input) {
  validatePolicy(policy, '.', {checkFiles: false});
  assert(nonempty(input.milestone_id), 'milestone_id required');
  assert(!policy.milestone_history.some(h => h.milestone === input.milestone_id), 'milestone already recorded; retries must use an unaccepted candidate identity');
  assert(['functional', 'infrastructure', 'documentation'].includes(input.kind ?? 'functional'), 'invalid milestone kind');
  const files = unique((input.changed_files ?? []).map(normalized));
  assert(files.every(f => !path.isAbsolute(f) && !f.split('/').includes('..')), 'changed files must be project-relative');
  const modules = unique(input.changed_modules ?? []);
  const suppliedTags = unique(input.feature_tags ?? []);
  assert(suppliedTags.every(t => policy.feature_tags.includes(t)), 'unknown feature tag');
  const explicitRisks = unique(input.risk_override ?? []);
  assert(explicitRisks.every(t => policy.risk_triggers.some(r => r.id === t)), 'unknown risk override');
  const matched = policy.change_impact.filter(rule => rule.paths.some(p => files.some(f => matches(p, f))) || rule.modules.some(m => modules.includes(m)));
  const unmappedFiles = files.filter(f => !policy.change_impact.some(r => r.paths.some(p => matches(p, f))));
  const unmappedModules = modules.filter(m => !policy.change_impact.some(r => r.modules.includes(m)));
  assert(files.length + modules.length + suppliedTags.length + explicitRisks.length > 0, 'empty change input requires an explicit scope');
  const tags = unique([...suppliedTags, ...matched.flatMap(r => r.feature_tags), ...policy.risk_triggers.filter(r => explicitRisks.includes(r.id)).flatMap(r => r.feature_tags)]);
  const risks = unique([...explicitRisks, ...matched.flatMap(r => r.risk_triggers), ...policy.risk_triggers.filter(r => r.feature_tags.some(t => tags.includes(t))).map(r => r.id)]);
  if (policy.scenario_registry.some(s => s.stability === 'flaky_candidate' && s.run_when.some(t => tags.includes(t)))) {
    if (!risks.includes('unexplained-gui-flake')) risks.push('unexplained-gui-flake');
    if (!tags.includes('unexplained-flake')) tags.push('unexplained-flake');
  }
  const functional = (input.kind ?? 'functional') === 'functional';
  // Documentation/test infrastructure never advances the counter or launches
  // GUI solely to service an unrelated functional cadence.
  const periodic = policy.periodic_regression;
  const projected = periodic.milestones_since_last_full === null ? null : periodic.milestones_since_last_full + (functional ? 1 : 0);
  const periodicDue = functional && (periodic.state !== 'KNOWN' || projected >= periodic.interval);
  const expandedDue = periodicDue || risks.length > 0;
  const selected = new Map();
  const reasons = [];
  const add = (scenario, reason) => {
    assert(scenario.status !== 'RETIRED' && scenario.status !== 'LOWER_LEVEL_ONLY', `ineligible required scenario ${scenario.id}`);
    const current = selected.get(scenario.id);
    if (current) current.reasons = unique([...current.reasons, reason]);
    else selected.set(scenario.id, {...scenario, reasons: [reason], execution_status: 'NOT_RUN'});
  };
  for (const scenario of policy.scenario_registry.filter(s => s.level === 'L3')) {
    if (scenario.run_when.some(t => tags.includes(t))) add(scenario, 'changed runtime boundary / explicit closure requirement');
  }
  if (expandedDue) {
    reasons.push(risks.length ? 'L4b mandatory: high-risk/shared change' : 'L4b mandatory: periodic cadence / unknown legacy baseline calibration');
    const expanded = policy.scenario_registry.filter(s => s.level === 'L4b' && (s.run_when.some(t => tags.includes(t)) || s.risk_tags.some(r => risks.includes(r)) || (periodicDue && s.default_periodic)));
    assert(expanded.length > 0, 'expanded regression due but no owner composition registered');
    for (const scenario of expanded) add(scenario, 'periodic/risk-triggered cross-feature composition');
  }
  const hasRuntimeGui = [...selected.values()].some(s => s.level === 'L3' || s.level === 'L4b');
  const skipped = [];
  for (const id of policy.golden_scenarios) {
    const scenario = policy.scenario_registry.find(s => s.id === id);
    const cover = [...selected.values()].find(s => s.level === 'L4b' && s.subsumes?.includes(id));
    if (cover) skipped.push({id, why: 'same workflow/postconditions composed in selected L4b; not removed from coverage', covered_by: cover.id});
    else if (hasRuntimeGui || input.release_candidate === true) add(scenario, 'routine critical workflow for integration/release');
    else skipped.push({id, why: 'pure/owning integration invariant covered at L0-L2; cadence/risk checked separately'});
  }
  for (const scenario of policy.scenario_registry.filter(s => s.level === 'L5')) {
    if (input.release_candidate === true) add(scenario, 'only after source freeze, quality and required L3/L4 PASS');
  }
  for (const scenario of policy.scenario_registry) {
    if (!selected.has(scenario.id) && !skipped.some(s => s.id === scenario.id)) skipped.push({id: scenario.id, why: scenario.level === 'L5' ? 'not a frozen release candidate' : 'unimpacted / periodic composition not due for this owner'});
  }
  const tests = unique(matched.flatMap(r => r.tests)).map(id => policy.test_registry.find(t => t.id === id));
  const required = Object.fromEntries(LEVELS.map(level => [level, level.startsWith('L0') || level === 'L1' || level === 'L2' ? tests.filter(t => t.level === level) : [...selected.values()].filter(s => s.level === level)]));
  const gui = [...selected.values()];
  const counts = {
    focused_new_feature_gui: gui.filter(s => s.level === 'L3' && !s.real_file).length,
    routine_golden_gui: gui.filter(s => s.level === 'L4a').length,
    real_file_gui: gui.filter(s => s.real_file).length,
    frozen_artifact_smoke: gui.filter(s => s.level === 'L5').length,
    expanded_gui: gui.filter(s => s.level === 'L4b').length,
    typical_gui_runs: gui.length,
  };
  const violations = Object.entries(counts).filter(([key, value]) => key in policy.budgets && value > policy.budgets[key]).map(([key, value]) => ({key, planned: value, soft_limit: policy.budgets[key]}));
  const override = input.budget_override_reason ? {budget_override_reason: input.budget_override_reason, risk_trigger: risks, required_scenarios: gui.map(s => s.id)} : null;
  if (override) assert(nonempty(override.budget_override_reason) && override.budget_override_reason.trim().length >= 12, 'budget override needs a meaningful bounded reason');
  const quarantined = gui.filter(s => s.stability === 'quarantined').map(s => s.id);
  const fixtureReview = gui.filter(s => s.requires_fixture_review).map(s => s.id);
  const status = unmappedFiles.length || unmappedModules.length ? 'NEEDS_IMPACT_REVIEW' : fixtureReview.length ? 'NEEDS_FIXTURE_REVIEW' : quarantined.length ? 'BLOCKED_TEST_INVESTIGATION' : violations.length && !override ? 'BUDGET_JUSTIFICATION_REQUIRED' : 'PLANNED';
  return {
    schema_version: 1, global_policy_digest: globalDigest(), policy_version: policy.policy_version, policy_digest: hash(policy), milestone: input.milestone_id,
    planning_input: structuredClone(input),
    milestone_kind: input.kind ?? 'functional', candidate_status: input.candidate_status ?? 'UNACCEPTED', status,
    changed_files: files, changed_modules: modules, feature_tags: tags, risk_triggers: risks,
    impact_rules: matched.map(r => r.id), unmapped_changes: {files: unmappedFiles, modules: unmappedModules}, fixture_review: fixtureReview,
    required, selected_scenario_ids: gui.map(s => s.id), skipped_periodic_tests: skipped,
    l4b_required: expandedDue, l4b_reasons: reasons, periodic_counter: {...periodic, prospective_after_acceptance: projected, due: periodicDue, advance_on_planning: false},
    estimated_gui_runs: gui.length, budget: {status: violations.length ? override ? 'JUSTIFIED_OVERRIDE' : 'JUSTIFICATION_REQUIRED' : 'WITHIN_SOFT_LIMIT', counts, violations, override},
    execution: {runs_tests: false, runs_gui: false, updates_acceptance: false, historical_gui_is_current_pass: false},
    artifact: input.artifact ?? null,
  };
}

export function classifyObservation(observation) {
  if (observation.not_run) return 'NOT_RUN';
  if (observation.foreground_lost || observation.clipboard_interference || observation.desktop_unavailable) return 'BLOCKED_ENVIRONMENT';
  if (observation.stale_uia_element || observation.dpi_runner_mismatch || observation.invalid_test_script) return 'FAIL_TEST_INFRA';
  if (observation.product_failure) return 'FAIL_PRODUCT';
  return observation.postconditions_verified === true && observation.runtime_healthy === true ? 'PASS' : 'NOT_RUN';
}

export function recordAcceptedMilestone(policy, event, plan) {
  // Pure state transition, exported for deterministic tests. CLI verifies
  // actual artifact/evidence before calling; partial/docs/retry never count.
  if (event.status !== 'ACCEPTED' || event.kind !== 'functional') return {changed: false, policy};
  assert(plan.milestone_kind === 'functional', 'functional acceptance requires functional plan');
  assert(plan.status === 'PLANNED' && plan.policy_digest === hash(policy), 'acceptance requires current valid plan');
  assert(object(plan.planning_input) && JSON.stringify(planVerification(policy, plan.planning_input)) === JSON.stringify(plan), 'plan changed or required coverage removed');
  assert(event.milestone === plan.milestone && /^[A-F0-9]{64}$/.test(event.artifact_hash ?? ''), 'acceptance identity mismatch');
  assert(!policy.milestone_history.some(h => h.milestone === event.milestone), 'milestone already recorded');
  assert(nonempty(event.date) && event.verified_proof === true, 'verified acceptance evidence required');
  assert(!plan.l4b_required || event.expanded_gui === true, 'required L4b not passed');
  assert(event.expanded_gui !== true || plan.required.L4b.length > 0, 'cannot reset counter without selected expanded regression');
  const next = structuredClone(policy);
  const periodicIds = policy.scenario_registry.filter(s => s.level === 'L4b' && s.default_periodic === true && s.status !== 'RETIRED').map(s => s.id);
  const fullCovered = event.expanded_gui === true && (policy.evidence_version !== 2 || (periodicIds.length > 0 && periodicIds.every(id => plan.selected_scenario_ids.includes(id))));
  next.milestone_history.push({milestone: event.milestone, status: 'ACCEPTED', kind: 'functional', expanded_gui: fullCovered, artifact_hash: event.artifact_hash, date: event.date, verification_profile: plan.selected_scenario_ids, reason: event.reason ?? 'verified required closure', ...(policy.evidence_version === 2 ? {risk_composition_passed: event.expanded_gui === true} : {})});
  if (next.current_candidate?.milestone === event.milestone) next.current_candidate = {...next.current_candidate, status: 'ACCEPTED', counted: true};
  for (const id of plan.selected_scenario_ids) {
    const scenario=next.scenario_registry.find(s=>s.id===id);
    scenario.last_passed_artifact=event.artifact_hash;scenario.last_passed_date=event.date;
  }
  if (fullCovered) {
    next.periodic_regression.state = 'KNOWN';
    next.periodic_regression.last_full_gui_milestone = event.milestone;
    next.periodic_regression.milestones_since_last_full = 0;
  } else {
    assert(next.periodic_regression.state === 'KNOWN', 'cannot advance an unknown expanded baseline');
    next.periodic_regression.milestones_since_last_full += 1;
  }
  next.periodic_regression.next_recommended_full = `approximately ${Math.max(0, next.periodic_regression.interval - next.periodic_regression.milestones_since_last_full)} accepted functional milestones after ${event.milestone}; earlier on risk`;
  return {changed: true, policy: next};
}

export function verifyAcceptanceProof(policy, event, plan, root) {
  assert(event.status === 'ACCEPTED' && event.kind === 'functional', 'proof is not accepted functional closure');
  assert(plan.milestone_kind === 'functional', 'functional acceptance requires functional plan');
  assert(object(plan.planning_input) && JSON.stringify(planVerification(policy, plan.planning_input)) === JSON.stringify(plan), 'plan changed or required coverage removed');
  const artifact = inside(root, event.artifact_path);
  let hostProvenance;
  if(policy.execution_profile === 'makepad-linux-wslc'){
    for(const id of plan.selected_scenario_ids){
      const s=policy.scenario_registry.find(s=>s.id===id),r=readJson(inside(root,s.file));
      const approved=approvedHostArtifact(root,policy,s,r);
      assert(approved.host.canonical_path===artifact && approved.host.sha256===event.artifact_hash,'actual artifact hash mismatch');
      hostProvenance=approved;
    }
    assert(hostProvenance,'WSLC acceptance requires an identity-bearing scenario');
  }
  assert(hostProvenance ? hostProvenance.host.sha256===event.artifact_hash : fs.existsSync(artifact) && hash(fs.readFileSync(artifact)) === event.artifact_hash, 'actual artifact hash mismatch');
  assert(!plan.artifact?.sha256 || plan.artifact.sha256 === event.artifact_hash, 'artifact differs from planned candidate');
  const quality = readJson(inside(root, event.quality_report));
  assert(Array.isArray(quality.gates) && quality.gates.length > 0 && quality.gates.every(g => g.exit_code === 0), 'quality gates not PASS');
  assert(quality.artifact?.sha256 === event.artifact_hash, 'quality artifact identity mismatch');
  for (const test of ['L0', 'L1', 'L2'].flatMap(level => plan.required[level])) {
    assert(quality.gates.some(g => g.id === test.id && g.exit_code === 0), `required lower-level gate missing ${test.id}`);
  }
  const freeze = readJson(inside(root, event.source_freeze));
  const freezeHash = hash(fs.readFileSync(inside(root, event.source_freeze)));
  assert(quality.source_freeze_sha256 === freezeHash && Number.isFinite(Date.parse(quality.completed_at)), 'quality source/timestamp evidence missing');
  assert(Array.isArray(freeze) && freeze.length > 0, 'actual source freeze missing');
  for (const source of freeze) {
    assert(nonempty(source.path) && /^[A-F0-9]{64}$/.test(source.sha256 ?? ''), 'invalid source freeze entry');
    const file = path.isAbsolute(source.path) ? path.resolve(source.path) : inside(root, source.path);
    assert(file.startsWith(path.resolve(root) + path.sep), 'source freeze entry outside consumer project');
    assert(fs.existsSync(file) && hash(fs.readFileSync(file)) === source.sha256, 'source changed after quality freeze');
  }
  assert(Array.isArray(event.scenario_results), 'scenario evidence missing');
  for (const id of plan.selected_scenario_ids) {
    const proof = event.scenario_results.find(p => p.id === id);
    assert(proof?.status === 'PASS' && proof.artifact_hash === event.artifact_hash, `required scenario not PASS ${id}`);
    const report = readJson(inside(root, proof.report));
    const scenario = policy.scenario_registry.find(s => s.id === id);
    const recipe = readJson(inside(root, scenario.file));
    const provenance = approvedHostArtifact(root,policy,scenario,recipe);
    assert((provenance?.host.canonical_path ?? path.resolve(recipe.application.command)) === artifact, `recipe executes a different artifact ${id}`);
    const run = readJson(inside(root, proof.run_manifest));
    assert(run.status === 'CAPTURED', `run envelope not finalized ${id}`);
    assert(run.milestone === plan.milestone && run.policy_digest === plan.policy_digest && run.scenario_id === id, `run identity mismatch ${id}`);
    assert(run.artifact_before === event.artifact_hash && run.artifact_after === event.artifact_hash, `run artifact not frozen ${id}`);
    assert(run.source_freeze_before === freezeHash && run.source_freeze_after === freezeHash, `run source identity mismatch ${id}`);
    assert(run.recipe_sha256 === hash(fs.readFileSync(inside(root, scenario.file))) && run.report_sha256 === hash(fs.readFileSync(inside(root, proof.report))), `run recipe/report integrity mismatch ${id}`);
    assert(Number.isFinite(Date.parse(run.started_at)) && Date.parse(run.completed_at) >= Date.parse(run.started_at), `invalid run timestamps ${id}`);
    if (scenario.level === 'L5') {
      assert(Date.parse(run.started_at) >= Date.parse(quality.completed_at), 'smoke must follow quality gates');
      for (const other of event.scenario_results.filter(p => p.id !== id)) {
        const prior = readJson(inside(root, other.run_manifest));
        assert(Date.parse(prior.completed_at) <= Date.parse(run.started_at), 'smoke must follow required GUI');
      }
    }
    assert(report.test === recipe.name || report.name === recipe.name, `raw report is not this scenario ${id}`);
    assert(report.status === 'PASSED' && report.summary?.failed === 0 && report.summary?.skipped === 0 && report.summary?.passed === report.summary?.total, `incomplete raw GUI report ${id}`);
    const expected = [...(recipe.setup ?? []), ...recipe.steps];
    const steps = report.steps?.filter(s => s.status !== 'PASS_AUTO_CLEANUP') ?? [];
    const all = [...expected, ...(recipe.teardown ?? [])];
    assert(steps.length === all.length && report.summary.total === report.steps.length, `incomplete raw recipe steps ${id}`);
    for (let index = 0; index < all.length; index++) {
      const label = all[index].step_id ?? (index < expected.length ? `step-${index}` : `teardown-${index - expected.length}`);
      const step = steps[index], expectedError = all[index].expect_error;
      // Only the exact frozen step can declare a refusal. Preserve its raw
      // response; v2 independently verifies the required postcondition/readback.
      const passed = Object.hasOwn(all[index], 'expect_error')
        ? nonempty(expectedError) && step.status === 'PASS_EXPECTED_ERROR' && step.response?.success === false && step.response?.error?.code === expectedError
        : step.status === 'PASS' && step.response?.success !== false && step.response?.error == null;
      assert(step.index === index && step.step === label && step.operation === all[index].op && passed, `missing or mismatched recipe step ${id}:${index}`);
    }
    const health = report.steps?.filter(s => s.operation === 'get_runtime_health') ?? [];
    assert(health.length > 0 && health.every(s => s.status === 'PASS' && s.response?.result?.healthy === true && s.response.result.process_alive === true), `runtime health evidence missing ${id}`);
    const stderr = report.steps?.filter(s => s.operation === 'get_runtime_stderr') ?? [];
    assert(stderr.length > 0 && stderr.every(s => s.status === 'PASS' && Array.isArray(s.response?.result) && s.response.result.length === 0), `runtime stderr not explicitly clean ${id}`);
  }
  const smoke = plan.required.L5;
  assert(smoke.length === (plan.planning_input.release_candidate === true ? 1 : 0), 'release candidate requires exactly one final artifact smoke');
  return {...event, verified_proof: true};
}

function atomicJson(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive: true});
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try {fs.writeFileSync(temporary, JSON.stringify(value, null, 2) + '\n', {flag: 'wx'}); fs.renameSync(temporary, file);}
  finally {if (fs.existsSync(temporary)) fs.unlinkSync(temporary);}
}
function argumentsMap(args) {
  const parsed = {};
  for (let i = 0; i < args.length; i += 2) {
    assert(args[i].startsWith('--') && args[i + 1] !== undefined, `invalid argument ${args[i]}`);
    const key = args[i].slice(2);
    if (['changed-file', 'changed-module', 'tag', 'risk'].includes(key)) (parsed[key] ??= []).push(args[i + 1]);
    else {assert(!(key in parsed), `duplicate argument ${key}`); parsed[key] = args[i + 1];}
  }
  return parsed;
}
export function runLegacyCli(args, defaultRoot = process.cwd()) {
  const command = args.shift();
  const options = argumentsMap(args);
  const allowed = {validate: ['root', 'policy'], plan: ['root', 'policy', 'input', 'milestone', 'changed-file', 'changed-module', 'tag', 'risk', 'kind', 'release', 'budget-override-reason', 'output'], record: ['root', 'policy', 'acceptance', 'plan']}[command];
  assert(allowed && Object.keys(options).every(key => allowed.includes(key)), 'unknown command/option');
  assert(options.release === undefined || ['true', 'false'].includes(options.release), 'release must be true or false');
  const root = path.resolve(options.root ?? defaultRoot);
  const policyFile = path.resolve(options.policy ?? path.join(root, 'verification/verification-policy.json'));
  const policy = readJson(policyFile);
  const validation = validatePolicy(policy, root);
  if (command === 'validate') {console.log(JSON.stringify(validation)); return;}
  if (command === 'plan') {
    const input = options.input ? readJson(path.resolve(options.input)) : {milestone_id: options.milestone, changed_files: options['changed-file'] ?? [], changed_modules: options['changed-module'] ?? [], feature_tags: options.tag ?? [], risk_override: options.risk ?? [], kind: options.kind ?? 'functional', release_candidate: options.release === 'true', budget_override_reason: options['budget-override-reason']};
    const plan = planVerification(policy, input);
    const output = path.resolve(options.output ?? path.join(root, 'verification/current-verification-plan.json'));
    assert(output.startsWith(path.join(root, 'verification') + path.sep), 'plan output must stay in project verification directory');
    atomicJson(output, plan);
    console.log(JSON.stringify({status: plan.status, milestone: plan.milestone, estimated_gui_runs: plan.estimated_gui_runs, l4b_required: plan.l4b_required, risks: plan.risk_triggers, budget: plan.budget.status, output}));
    if (plan.status !== 'PLANNED') process.exitCode = 2;
    return;
  }
  if (command === 'record') {
    const event = readJson(path.resolve(options.acceptance));
    if (event.status !== 'ACCEPTED' || event.kind !== 'functional') {console.log(JSON.stringify({changed: false, reason: 'only accepted functional milestones count'})); return;}
    const plan = readJson(path.resolve(options.plan));
    const verified = verifyAcceptanceProof(policy, event, plan, root);
    const updated = recordAcceptedMilestone(policy, verified, plan);
    validatePolicy(updated.policy, root);
    // One atomic JSON includes counter + append-only history; no split-file
    // partial update. Exclusive lock protects concurrent acceptance writers.
    const lock = `${policyFile}.acceptance.lock`;
    const fd = fs.openSync(lock, 'wx');
    try {
      assert(hash(readJson(policyFile)) === plan.policy_digest, 'policy changed during acceptance verification');
      atomicJson(policyFile, updated.policy);
    } finally {fs.closeSync(fd); fs.unlinkSync(lock);}
    console.log(JSON.stringify({changed: true, milestone: event.milestone, periodic: updated.policy.periodic_regression}));
    return;
  }
  fail('use validate, plan or record; this tool never runs GUI/tests');
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {runLegacyCli(process.argv.slice(2));} catch (error) {console.error(error.message); process.exitCode = 1;}
}
