// One planner and state transition implementation: v2 adds binding/admission/evidence
// to the extracted engine, not a competing runner. No execution is performed here.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import * as engine from './verification-policy.mjs';
import * as envelope from './verification-run-envelope.mjs';
import {globalPolicy, globalDigest, digest, demand} from './global-policy.mjs';
import {verifyWslcExecutableProvenance, approvedHostArtifact, observeHostFile, parseIdentityJson} from './executable-provenance.mjs';
export const CORE_VERSION='1.0.0';
export function coreDigest() {
  const names=['global-policy.json','global-policy.mjs','verification-policy.mjs','verification-run-envelope.mjs','executable-provenance.mjs','index.mjs'];
  return digest(Object.fromEntries(names.map(n=>[n,digest(fs.readFileSync(new URL(n,import.meta.url)))])));
}
export {globalPolicy, globalDigest, digest};
export const LEVEL_MAPPING=Object.freeze({ToolkitL0:['L0'],ToolkitL1:['L1'],ToolkitL2:['L2','L3'],ToolkitL3:['L2','L3','L4a','L4b'],ToolkitL4:['L5']});
const nonempty=v=>typeof v==='string' && v.trim().length>0;
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export function owned(root, ref) {
  demand(nonempty(ref),'missing project reference');
  const absolute=path.resolve(root,ref), base=fs.realpathSync(root);
  demand(absolute.startsWith(path.resolve(root)+path.sep),'reference outside project');
  let parent=absolute;
  while(!fs.existsSync(parent))parent=path.dirname(parent);
  const real=fs.realpathSync(parent);
  demand(real===base || real.startsWith(base+path.sep),'symlink reference outside project');
  return absolute;
}
const fileHash=(root,ref)=>digest(fs.readFileSync(owned(root,ref)));
const read=(root,ref)=>engine.readJson(owned(root,ref));
export function bindPolicy(policy,binding) {
  demand(binding?.schema_version===1 && binding.core_version===CORE_VERSION,'unsupported core binding version');
  demand(nonempty(binding.project_id) && /^[a-z0-9][a-z0-9._-]*$/i.test(binding.project_id),'invalid project identity');
  const g=globalPolicy();
  demand(binding.global_policy_version===g.policy_version && binding.evidence_version===g.evidence.version,'unsupported global/evidence binding version');
  demand(['makepad-windows','makepad-semantic','makepad-linux-wslc','gpu-rendering','scheduler-workers'].includes(binding.profile),'unknown execution profile');
  const p=structuredClone(policy);
  p.project_id=binding.project_id;p.execution_profile=binding.profile;p.core_version=CORE_VERSION;
  p.global_policy_version=g.policy_version;p.evidence_version=2;p.core_binding_digest=digest(binding);
  // Domain registries remain authoritative. Global risks extend, never overwrite them.
  for(const r of g.risks){
    const tags=r.id==='test-infrastructure'?[]:r.feature_tags.filter(t=>p.feature_tags.includes(t));
    const domain=p.risk_triggers.find(v=>v.id===r.id);
    if(domain)domain.feature_tags=[...new Set([...domain.feature_tags,...tags])];
    else p.risk_triggers.push({...r,feature_tags:tags});
  }
  p.dependency_impact=binding.dependency_impact??[];
  demand(p.scenario_registry.some(s=>s.level==='L4b'&&s.default_periodic===true&&s.status!=='RETIRED'),'registered periodic composition required');
  engine.validatePolicy(p,'.',{checkFiles:false});
  return p;
}
export function loadProject(root) {
  const policy=read(root,'verification/verification-policy.json');
  const binding=read(root,'verification/toolkit-core.json');
  return bindPolicy(policy,binding);
}
function resolvedInput(policy,input) {
  const modules=new Set(input.changed_modules??[]), dependencies=policy.dependency_impact??[];
  for(const rule of policy.change_impact)if(rule.paths.some(pattern=>(input.changed_files??[]).some(file=>engine.matches(pattern,file.replaceAll('\\','/')))))for(const m of rule.modules)modules.add(m);
  demand(Array.isArray(dependencies),'invalid dependency impact');
  const known=new Set(policy.change_impact.flatMap(r=>r.modules));
  for(const d of dependencies)demand(known.has(d.owner) && Array.isArray(d.dependents) && d.dependents.every(m=>known.has(m)),'unregistered dependency impact owner');
  let changed=true;while(changed){changed=false;for(const d of dependencies)if(modules.has(d.owner))for(const m of d.dependents)if(!modules.has(m)){modules.add(m);changed=true;}}
  return {...input,changed_modules:[...modules].sort()};
}
export function requirements(policy,plan) {
  const selected=['L0','L1','L2'].flatMap(l=>plan.required[l]);
  const gui=['L3','L4a','L4b','L5'].flatMap(l=>plan.required[l]);
  const resources=new Set([...selected,...gui].flatMap(s=>s.resources??[]));
  for(const s of gui){
    if(s.cost_factors.desktop_exclusivity)resources.add('desktop_lease');
    if(s.cost_factors.clipboard_ownership)resources.add('native_clipboard');
  }
  if(gui.length){
    if(policy.execution_profile==='makepad-windows')resources.add('physical_input');
    if(['makepad-linux-wslc','gpu-rendering'].includes(policy.execution_profile))resources.add('wslc_session');
    if(policy.execution_profile==='gpu-rendering')resources.add('gpu');
  }
  const cost={process_launches:gui.reduce((n,s)=>n+(s.cost_factors.process_window_launches??1),0),native_actions:gui.reduce((n,s)=>n+(s.cost_factors.native_actions??0),0),captures:gui.reduce((n,s)=>n+(s.cost_factors.captures??0),0),build_executions:selected.filter(s=>(s.resources??[]).includes('large_build')).length,vm_starts:gui.filter(s=>(s.resources??[]).includes('wslc_session')).length,assertions:'not a budget metric'};
  const supported=['desktop_lease','physical_input','native_clipboard','wslc_session','gpu','large_build','worker_lease'];
  demand([...resources].every(r=>supported.includes(r)),'unknown required resource');
  const guards=globalPolicy().resource_guards;
  const ram=guards.min_available_physical_ram_mib;
  demand(Number.isSafeInteger(ram) && ram>0 && ram<=Number.MAX_SAFE_INTEGER/1048576
    && guards.wslc_min_available_ram_mib===ram,'invalid or inconsistent physical RAM policy');
  return {resources:[...resources].sort(),min_available_ram_mib:resources.has('wslc_session')||resources.has('large_build')?ram:0,no_unbudgeted_heavy_parallelism:resources.has('large_build')||resources.has('wslc_session')||resources.has('gpu'),cost};
}
export function resourceAdmission(required,available) {
  if(!required.resources.length)return {status:'ADMITTED',blockers:[]};
  if(!available)return {status:'NOT_CHECKED',blockers:['runtime admission required before execution']};
  const blockers=required.resources.filter(r=>available[r]!==true);
  if(required.min_available_ram_mib && (!Number.isFinite(available.available_ram_mib)||available.available_ram_mib<required.min_available_ram_mib))blockers.push('insufficient_available_ram');
  if(required.no_unbudgeted_heavy_parallelism && available.heavy_workloads_active!==0)blockers.push('unbudgeted_heavy_parallelism');
  return {status:blockers.length?'BLOCKED_ENVIRONMENT':'ADMITTED',blockers};
}
// This explicit operator contract waives only an unknown physical-free-RAM
// observation for a source-approved two-module WSLC profile. The ordinary
// resourceAdmission function and global/Focus thresholds remain unchanged.
function operatorRamWaiver(policy,input,selected,{fresh=false,at=Date.now()}={}) {
  const available=input.available_resources, a=available?.ram_admission;
  if(a?.schema!=='toolkit-module-shell-core-ram-waiver-v1')return null;
  demand(policy.execution_profile==='makepad-linux-wslc'&&nonempty(input.trusted_root),'operator RAM scope requires a trusted WSLC consumer root');
  const root=fs.realpathSync(input.trusted_root);
  demand(root===path.resolve(input.trusted_root),'operator RAM root must be canonical');
  demand(available.host_runtime_budget_mib===2560&&!Object.hasOwn(available,'available_ram_mib')&&
    a.status==='USER_WAIVED'&&a.available_memory_query_performed===false&&a.resource_admitted===false&&
    a.container_memory_bytes===2147483648&&a.container_cpus===1&&a.nested_increment_kib===0,
  'operator RAM waiver cannot claim a memory measurement or alter limits');
  const ref=value=>{
    demand(nonempty(value?.path)&&!path.isAbsolute(value.path)&&/^[A-F0-9]{64}$/.test(value.sha256??''),'operator RAM receipt reference missing');
    const file=observeHostFile(root,value.path,{limit:65536,capture:true});
    demand(file.sha256===value.sha256,'operator RAM receipt/profile bytes changed');
    return parseIdentityJson(file.content);
  };
  const native=ref(a.receipt),profile=ref(a.profile);
  const expected={schema:'toolkit-makepad-dev-app-module-shell-host-admission-v1',utc:a.utc,owner:a.owner,
    source_manifest_sha256:a.source_manifest_sha256,host_ram_mode:'USER_WAIVED',status:'USER_WAIVED',
    available_memory_query_performed:false,minimum_free_bytes:2684354560,minimum_free_kib:2621440,
    container_memory_bytes:2147483648,container_cpus:1,nested_increment_kib:0,
    active_compiler_observation_performed:true,active_rust_compilers:[],resource_admitted:false,scope:'one_outer_runtime_admission'};
  demand(Object.keys(native).length===Object.keys(expected).length&&Object.entries(expected).every(([k,v])=>same(native[k],v)),
    'operator RAM native observation/positive budget mismatch');
  const observed=Date.parse(a.utc),checked=Date.parse(a.checked_at);
  demand(Number.isFinite(observed)&&Number.isFinite(checked)&&checked>=observed&&checked-observed<=120000,
    'operator RAM observation was stale at planning');
  if(fresh)demand(at>=observed&&at-observed<=120000&&checked<=at,'operator RAM observation is not fresh before dispatch');
  demand(nonempty(a.owner)&&selected.length>0,'operator RAM owner/selected scenario missing');
  for(const id of selected){
    const scenario=policy.scenario_registry.find(s=>s.id===id),c=scenario?.executable_provenance;
    demand(same(c?.profile,a.profile)&&c?.source_manifest?.sha256===a.source_manifest_sha256,'operator RAM scenario/profile/source join mismatch');
    const recipe=read(root,scenario.file),approved=approvedHostArtifact(root,policy,scenario,recipe);
    demand(approved?.profile.profile_kind==='ModuleShell'&&profile.profile_kind==='ModuleShell'&&
      approved.profile.owner===a.owner&&profile.owner===a.owner&&profile.module_shell?.source_manifest_sha256===a.source_manifest_sha256,
    'operator RAM waiver requires the actual approved ModuleShell artifact');
  }
  return {schema:a.schema,status:'USER_WAIVED',root,receipt:a.receipt,profile:a.profile,utc:a.utc,checked_at:a.checked_at,
    owner:a.owner,source_manifest_sha256:a.source_manifest_sha256,positive_budget_mib:2560,available_memory_observed:false};
}
function scopedAdmission(required,available,waiver) {
  const ordinary=resourceAdmission(required,available);
  if(!waiver)return ordinary;
  demand(required.min_available_ram_mib>0&&required.min_available_ram_mib<=waiver.positive_budget_mib&&
    required.resources.includes('wslc_session')&&!required.resources.includes('large_build'),'operator RAM waiver does not cover these requirements');
  demand(same(ordinary.blockers,['insufficient_available_ram']),'operator RAM waiver cannot bypass another resource blocker');
  return {status:'ADMITTED',blockers:[],waived_blockers:['insufficient_available_ram'],operator_ram:waiver};
}
function plannedProject(policy,input,fresh) {
  demand(policy.core_version===CORE_VERSION && policy.evidence_version===2,'versioned project binding required');
  const plan=engine.planVerification(policy,resolvedInput(policy,input));
  // A selected interaction also requires its registered lower-level boundary
  // coverage, including when it was selected by explicit risk/cadence alone.
  const ids=new Set(plan.selected_scenario_ids.flatMap(id=>policy.scenario_registry.find(s=>s.id===id).lower_level_coverage));
  for(const level of ['L0','L1','L2'])for(const test of policy.test_registry.filter(t=>t.level===level&&ids.has(t.id)))if(!plan.required[level].some(t=>t.id===test.id))plan.required[level].push(test);
  const required=requirements(policy,plan), waiver=operatorRamWaiver(policy,input,plan.selected_scenario_ids,{fresh}),
    admission=scopedAdmission(required,input.available_resources,waiver);
  const result={...plan,plan_version:2,core_version:CORE_VERSION,core_implementation_digest:coreDigest(),project_id:policy.project_id,execution_profile:policy.execution_profile,planning_input:structuredClone(input),resource_requirements:required,resource_admission:admission};
  if(plan.status==='PLANNED' && admission.status==='BLOCKED_ENVIRONMENT')result.status='BLOCKED_ENVIRONMENT';
  if(plan.selected_scenario_ids.some(id=>policy.scenario_registry.find(s=>s.id===id).stability==='flaky_candidate'))result.status='BLOCKED_TEST_INVESTIGATION';
  result.plan_digest=digest(result);
  return result;
}
export function planProject(policy,input) {return plannedProject(policy,input,true);}
export function validatePlan(policy,plan) {
  demand(same(plannedProject(policy,plan.planning_input,false),plan),'stale policy/global binding or forged plan');
  demand(plan.status==='PLANNED','plan is not executable/acceptable');
}
export function classifyResult(observation) {
  const old=engine.classifyObservation(observation);
  if(old!=='PASS')return old;
  return observation.action_dispatched===true && observation.required_evidence_verified===true && observation.cleanup_verified===true && observation.evidence_origin==='real'?'PASS':'NOT_RUN';
}
export function beginRun(root,policy,plan,id,freeze) {
  validatePlan(policy,plan);
  if(plan.resource_admission.operator_ram){
    demand(fs.realpathSync(root)===plan.resource_admission.operator_ram.root,'operator RAM consumer root mismatch');
    operatorRamWaiver(policy,plan.planning_input,plan.selected_scenario_ids,{fresh:true});
    const frozen=read(root,freeze),waiver=plan.resource_admission.operator_ram;
    for(const ref of [waiver.receipt,waiver.profile])demand(frozen.some(e=>e.path===ref.path&&e.sha256===ref.sha256),
      'operator RAM receipt/profile must be frozen before dispatch');
  }
  demand(plan.resource_admission.status==='ADMITTED','BLOCKED_ENVIRONMENT: resources must be admitted before capture/execution');
  const base=engine.planVerification(policy,resolvedInput(policy,plan.planning_input));
  const run=envelope.beginEnvelope(root,policy,base,id,freeze);
  return {...run,schema_version:2,project_id:policy.project_id,core_version:CORE_VERSION,global_policy_digest:globalDigest(),plan_digest:plan.plan_digest,run_id:crypto.randomUUID(),evidence_origin:'NOT_RUN',
    ...(plan.resource_admission.operator_ram?{operator_ram_admission:plan.resource_admission.operator_ram}:{})};
}
export function finishRun(root,run,reportFile,observationFile) {
  demand(run.schema_version===2 && nonempty(run.run_id),'v2 run identity required');
  demand(run.global_policy_digest===globalDigest(),'global policy changed during capture');
  const done=envelope.finishEnvelope(root,run,reportFile);
  // Observation sidecar is produced by the existing executor, never by this tool.
  demand(fs.statSync(owned(root,observationFile)).mtimeMs+1>=Date.parse(run.started_at),'observation predates this run');
  return {...done,observation_path:path.relative(root,owned(root,observationFile)),observation_sha256:fileHash(root,observationFile),evidence_origin:'captured; not accepted'};
}
export function expectedPostcondition(scenario,step,index) {
  const contract=scenario.postcondition_contracts?.find(c=>c.index===index);
  if(contract){
    demand(contract.operation===step.op && Object.hasOwn(contract,'expected_state') && contract.expected_state!==null,'invalid consumer-owned postcondition contract');
    return contract.expected_state;
  }
  // Existing public operations with a universal observed state. Other actions
  // require explicit consumer expectations; no fabricated acknowledgement default.
  const defaults={'session.open':{session_open:true},'session.close':{session_closed:true},get_runtime_health:{healthy:true,process_alive:true},get_runtime_stderr:[]};
  demand(Object.hasOwn(defaults,step.op),`missing consumer postcondition contract for ${step.op}:${index}`);
  return defaults[step.op];
}
export function verifyEvidence(root,policy,event,plan) {
  validatePlan(policy,plan);
  demand(plan.resource_admission.status==='ADMITTED','BLOCKED_ENVIRONMENT: required resources not admitted');
  demand(event.project_id===policy.project_id,'acceptance project identity mismatch');
  demand(event.evidence_version===2,'v2 evidence required; legacy reports remain history');
  const expected=plan.selected_scenario_ids, proofs=event.scenario_results??[];
  demand(Array.isArray(proofs) && proofs.length===expected.length && new Set(proofs.map(p=>p.id)).size===proofs.length && proofs.every(p=>expected.includes(p.id)),'exact scenario IDs required');
  // Canonicalize every evidence/source/artifact reference before the legacy verifier.
  for(const ref of [event.artifact_path,event.source_freeze,event.quality_report,...policy.scenario_registry.filter(s=>expected.includes(s.id)).map(s=>s.file),...proofs.flatMap(p=>[p.report,p.run_manifest])])owned(root,ref);
  for(const entry of read(root,event.source_freeze))owned(root,entry.path);
  const base=engine.planVerification(policy,resolvedInput(policy,plan.planning_input));
  const verified=engine.verifyAcceptanceProof(policy,event,base,root);
  const quality=read(root,event.quality_report);
  if(['L0','L1','L2'].flatMap(l=>plan.required[l]).some(t=>(t.resources??[]).length)){
    const waiver=operatorRamWaiver(policy,{...plan.planning_input,available_resources:quality.available_resources},plan.selected_scenario_ids);
    demand(scopedAdmission(plan.resource_requirements,quality.available_resources,waiver).status==='ADMITTED','BLOCKED_ENVIRONMENT: lower-level resource proof missing');
  }
  for(const gate of ['L0','L1','L2'].flatMap(l=>plan.required[l]))demand(quality.gates.some(g=>g.id===gate.id&&g.exit_code===0),`required integration/unit gate missing: ${gate.id}`);
  const runs=new Set(), correlations=new Set();
  for(const p of proofs){
    const run=read(root,p.run_manifest),obs=read(root,run.observation_path),recipe=read(root,policy.scenario_registry.find(s=>s.id===p.id).file);
    demand(run.schema_version===2 && run.project_id===policy.project_id && run.plan_digest===plan.plan_digest && run.global_policy_digest===globalDigest(),'run project/policy/plan binding mismatch');
    if(plan.resource_admission.operator_ram){
      demand(fs.realpathSync(root)===plan.resource_admission.operator_ram.root&&same(run.operator_ram_admission,plan.resource_admission.operator_ram),
        'operator RAM run/root/receipt binding mismatch');
      const age=Date.parse(run.started_at)-Date.parse(run.operator_ram_admission.utc);
      demand(age>=0&&age<=120000,'operator RAM launch-time observation stale');
    }
    demand(nonempty(run.run_id)&&!runs.has(run.run_id),'duplicate/missing run identity');runs.add(run.run_id);
    demand(fileHash(root,run.observation_path)===run.observation_sha256,'observation hash mismatch');
    demand(obs.schema_version===2 && obs.evidence_origin==='real' && obs.producer_kind==='native-runtime-observer','mock/forged producer is not real evidence');
    demand(obs.project_id===policy.project_id && obs.scenario_id===p.id && obs.run_id===run.run_id && obs.plan_digest===plan.plan_digest,'observation correlation mismatch');
    demand(obs.runtime?.artifact_sha256===event.artifact_hash && Number.isSafeInteger(obs.runtime.pid) && obs.runtime.pid>0 && nonempty(obs.runtime.namespace) && nonempty(obs.runtime.platform) && Number.isFinite(Date.parse(obs.runtime.started_at)) && Date.parse(obs.runtime.started_at)>=Date.parse(run.started_at) && Date.parse(obs.runtime.started_at)<=Date.parse(run.completed_at),'runtime identity/freshness missing');
    const scenario=policy.scenario_registry.find(s=>s.id===p.id);
    verifyWslcExecutableProvenance(root,policy,scenario,recipe,event,run,obs);
    // Identity-bearing consumers bind owner/session to frozen, consumer-owned
    // postconditions. Do not accept contradictory optional metadata merely
    // because its sidecar was rehashed. Legacy consumers without these fields
    // keep their existing contracts; there is no fabricated default identity.
    const contracts=scenario.postcondition_contracts??[];
    const owners=[...new Set(contracts.map(c=>c.expected_state?.owner).filter(nonempty))];
    const sessions=[...new Set(contracts.map(c=>c.expected_state?.session_id??c.expected_state?.SessionId).filter(nonempty))];
    const boundIdentity=owners.length>0||sessions.length>0;
    const runtimeSession=obs.runtime.session_id??obs.runtime.SessionId;
    if(boundIdentity){
      demand(owners.length===1&&obs.runtime.owner===owners[0],'runtime owner identity mismatch');
      demand(sessions.length===1&&runtimeSession===sessions[0],'runtime SessionId identity mismatch');
    }
    if(scenario.adapter_identity){
      const adapter=scenario.adapter_identity;
      demand(nonempty(adapter.path)&&fileHash(root,adapter.path)===adapter.sha256&&obs.runtime.adapter_sha256===adapter.sha256,'runtime adapter identity mismatch');
      demand(read(root,event.source_freeze).some(f=>owned(root,f.path)===owned(root,adapter.path)&&f.sha256===adapter.sha256),'adapter implementation absent from source freeze');
    }
    if((scenario.resources??[]).includes('physical_input')||plan.execution_profile==='makepad-windows')demand(nonempty(String(obs.runtime.window_id??'')),'window identity missing');
    demand(obs.health?.healthy===true && obs.health.process_alive===true && nonempty(obs.health.observation_source),'runtime health observation missing');
    const steps=[...(recipe.setup??[]),...recipe.steps,...(recipe.teardown??[])];
    demand(Array.isArray(obs.steps)&&obs.steps.length===steps.length,'setup/steps/teardown observation incomplete');
    for(let i=0;i<steps.length;i++){
      const s=obs.steps[i];
      if(boundIdentity){
        demand(s.owner===obs.runtime.owner,'runtime owner identity mismatch');
        demand((s.session_id??s.SessionId)===runtimeSession,'runtime SessionId identity mismatch');
      }
      demand(s.index===i && s.operation===steps[i].op && s.action_dispatched===true && s.postcondition_verified===true && nonempty(s.observation_source),'dispatch acknowledgement is not actual postcondition');
      demand(nonempty(s.correlation_id)&&!correlations.has(s.correlation_id),'duplicate/missing action correlation');correlations.add(s.correlation_id);
      const start=Date.parse(s.dispatched_at), end=Date.parse(s.observed_at);
      demand(Number.isFinite(start)&&end>=start&&start>=Date.parse(run.started_at)&&end<=Date.parse(run.completed_at),'stale/out-of-order observation');
      demand(end>=Date.parse(obs.runtime.started_at) && (s.operation==='session.open'||start>=Date.parse(obs.runtime.started_at)),'process observation predates runtime creation');
      demand(nonempty(s.evidence_path)&&fileHash(root,s.evidence_path)===s.evidence_sha256,'postcondition evidence missing or stale');
      const state=read(root,s.evidence_path);
      const expected=expectedPostcondition(scenario,steps[i],i);
      demand(state.evidence_origin==='real' && state.run_id===run.run_id && state.correlation_id===s.correlation_id && state.operation===s.operation && Object.hasOwn(state,'actual_state') && same(state.actual_state,expected) && same(state.expected_state,expected) && state.observation_source===s.observation_source,'postcondition readback not correlated or not matched to trusted recipe/consumer contract');
    }
    const captures=obs.captures??(obs.capture?[obs.capture]:[]);
    demand(Array.isArray(captures),'invalid capture evidence');
    for(const capture of captures){
      demand(nonempty(capture.evidence_path)&&fileHash(root,capture.evidence_path)===capture.evidence_sha256,'capture hash mismatch');
      const captured=Date.parse(capture.captured_at);
      demand(Number.isFinite(captured)&&captured>=Date.parse(run.started_at)&&captured>=Date.parse(obs.runtime.started_at)&&captured<=Date.parse(run.completed_at),'capture timestamp is stale');
      if(boundIdentity){
        demand(capture.owner===obs.runtime.owner,'runtime owner identity mismatch');
        demand((capture.session_id??capture.SessionId)===runtimeSession,'runtime SessionId identity mismatch');
      }
      if(scenario.require_native_captures===true){
        const step=obs.steps.find(s=>s.correlation_id===capture.correlation_id);
        demand(capture.run_id===run.run_id&&step?.operation==='screenshot_window'&&captured+1>=Date.parse(step.dispatched_at)&&captured<=Date.parse(step.observed_at),'capture/action correlation missing or stale');
        demand(capture.window_id===obs.runtime.window_id,'capture window identity mismatch');
        const bytes=fs.readFileSync(owned(root,capture.evidence_path));
        demand(bytes.length>24&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))&&bytes.readUInt32BE(16)>0&&bytes.readUInt32BE(20)>0,'invalid native PNG evidence');
        if(scenario.require_native_visual_review===true){
          const ref=capture.visual_review_evidence;
          demand(capture.visual_review==='REVIEWED'&&nonempty(ref?.path)&&fileHash(root,ref.path)===ref.sha256,'actual native frame visual review missing');
          const review=read(root,ref.path);
          demand(review.schema==='toolkit-native-frame-visual-review-v1'&&review.actual_visual_review===true&&review.run_id===run.run_id&&review.captures?.some(c=>c.path===capture.evidence_path&&c.sha256===capture.evidence_sha256&&nonempty(c.observed_text)&&Date.parse(c.reviewed_at)>=captured&&Date.parse(c.reviewed_at)<=Date.parse(run.completed_at)),'native visual review is stale or uncorrelated');
        }
      }
    }
    if(scenario.require_native_captures===true){
      const requiredCaptures=obs.steps.filter(s=>s.operation==='screenshot_window');
      demand(requiredCaptures.length>0&&captures.length===requiredCaptures.length&&requiredCaptures.every(s=>captures.filter(c=>c.correlation_id===s.correlation_id).length===1),'required native captures missing/duplicated');
    }
    for(const key of ['pointer_buttons_released','modifiers_released','input_leases_released','processes_exited','windows_closed','worker_resources_released'])demand(obs.cleanup?.[key]===true,`cleanup missing: ${key}`);
    demand(nonempty(obs.cleanup.evidence_path)&&fileHash(root,obs.cleanup.evidence_path)===obs.cleanup.evidence_sha256,'cleanup telemetry missing');
    const cleanup=read(root,obs.cleanup.evidence_path);
    demand(cleanup.run_id===run.run_id && cleanup.evidence_origin==='real','cleanup identity mismatch');
    for(const key of ['orphan_processes','stuck_pointer_buttons','stuck_modifiers','active_input_leases','stale_windows','leaked_resources'])demand(cleanup[key]===0,`cleanup telemetry nonzero/missing: ${key}`);
    const waiver=operatorRamWaiver(policy,{...plan.planning_input,available_resources:obs.available_resources},plan.selected_scenario_ids);
    if(plan.resource_admission.operator_ram)demand(waiver&&same(waiver.receipt,plan.resource_admission.operator_ram.receipt)&&
      same(waiver.profile,plan.resource_admission.operator_ram.profile),'operator RAM runtime receipt/profile changed');
    demand(scopedAdmission(plan.resource_requirements,obs.available_resources,waiver).status==='ADMITTED','BLOCKED_ENVIRONMENT: runtime resources not admitted');
    if(plan.resource_requirements.resources.includes('gpu'))demand(nonempty(obs.gpu?.gpu_actual) && nonempty(obs.gpu.renderer) && obs.gpu.verification_source==='makepad_runtime_log','actual Makepad GPU proof missing');
    if(scenario.expected_gpu?.mode==='required')demand(obs.gpu.gpu_match===true && String(obs.gpu.gpu_actual).toLowerCase().includes(scenario.expected_gpu.vendor.toLowerCase()) && !/llvmpipe/i.test(obs.gpu.gpu_actual),'required runtime GPU mismatch');
  }
  return {...verified,verified_proof:true,verification_scope:'real-evidence-contract-v2'};
}
function atomic(file,value) {
  const tmp=file+'.'+crypto.randomUUID()+'.tmp';
  try{fs.writeFileSync(tmp,JSON.stringify(value,null,2)+'\n',{flag:'wx'});fs.renameSync(tmp,file);}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp);}
}
export function recordProject(root,event,plan) {
  const file=owned(root,'verification/verification-policy.json'), lock=file+'.acceptance.lock';
  const fd=fs.openSync(lock,'wx');
  try{
    const raw=engine.readJson(file), policy=loadProject(root);
    if(event.status!=='ACCEPTED'||event.kind!=='functional')return {changed:false,reason:'only accepted functional milestones count'};
    const requestDigest=digest({event,plan});
    const prior=raw.milestone_history.find(h=>h.milestone===event.milestone);
    if(prior){demand(prior.acceptance_request_digest===requestDigest,'conflicting duplicate acceptance');return {changed:false,reason:'idempotent verified acceptance replay'};}
    const verified=verifyEvidence(root,policy,event,plan), base=engine.planVerification(policy,resolvedInput(policy,plan.planning_input));
    const updated=engine.recordAcceptedMilestone(policy,verified,base).policy;
    // Only consumer state/history fields persist: global rules never replace its manifest.
    const next={...raw,milestone_history:updated.milestone_history,current_candidate:updated.current_candidate,periodic_regression:updated.periodic_regression,scenario_registry:updated.scenario_registry};
    next.milestone_history.at(-1).acceptance_request_digest=requestDigest;
    engine.validatePolicy(next,root);atomic(file,next);
    return {changed:true,milestone:event.milestone,periodic:next.periodic_regression};
  }finally{fs.closeSync(fd);fs.unlinkSync(lock);}
}
function options(args) {
  const o={};for(let i=0;i<args.length;i+=2){demand(args[i].startsWith('--')&&args[i+1]!==undefined,'invalid argument');const k=args[i].slice(2);if(['changed-file','changed-module','tag','risk'].includes(k))(o[k]??=[]).push(args[i+1]);else{demand(!(k in o),'duplicate option');o[k]=args[i+1];}}return o;
}
export function runCli(args,defaultRoot=process.cwd()) {
  const command=args.shift(),o=options(args);
  const allowed={validate:['root','policy'],plan:['root','policy','input','milestone','changed-file','changed-module','tag','risk','kind','release','budget-override-reason','output'],verify:['root','acceptance','plan'],record:['root','policy','acceptance','plan']}[command];
  demand(allowed&&Object.keys(o).every(k=>allowed.includes(k)),'unknown command/option');
  const root=path.resolve(o.root??defaultRoot);
  if(o.policy)demand(path.resolve(o.policy)===owned(root,'verification/verification-policy.json'),'authoritative manifest required');
  const policy=loadProject(root);let result;
  if(command==='validate')result=engine.validatePolicy(policy,root);
  else if(command==='plan'){
    demand(o.release===undefined||['true','false'].includes(o.release),'release must be true or false');
    const input=o.input?engine.readJson(path.resolve(o.input)):{milestone_id:o.milestone,changed_files:o['changed-file']??[],changed_modules:o['changed-module']??[],feature_tags:o.tag??[],risk_override:o.risk??[],kind:o.kind??'functional',release_candidate:o.release==='true',budget_override_reason:o['budget-override-reason']};
    result=planProject(policy,input);
    const output=owned(root,o.output??'verification/current-verification-plan.json');demand(output.startsWith(path.join(root,'verification')+path.sep),'plan output must be verification-local');fs.mkdirSync(path.dirname(output),{recursive:true});atomic(output,result);if(result.status!=='PLANNED')process.exitCode=2;
  }else{
    const event=engine.readJson(path.resolve(o.acceptance)),plan=engine.readJson(path.resolve(o.plan));
    result=command==='verify'?verifyEvidence(root,policy,event,plan):recordProject(root,event,plan);
  }
  console.log(JSON.stringify(result));return result;
}
export function runCaptureCli(args,defaultRoot=process.cwd()) {
  const command=args.shift(),o=options(args),root=path.resolve(o.root??defaultRoot);
  const allowed={begin:['root','plan','scenario','source-freeze','output'],finish:['root','run','report','observations']}[command];
  demand(allowed&&Object.keys(o).every(k=>allowed.includes(k)),'unknown envelope option');
  let run,file;
  if(command==='begin'){run=beginRun(root,loadProject(root),read(root,o.plan),o.scenario,o['source-freeze']);file=owned(root,o.output);demand(file.startsWith(path.join(root,'verification')+path.sep),'envelope output must be verification-local');fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,JSON.stringify(run,null,2)+'\n',{flag:'wx'});}
  else{file=owned(root,o.run);demand(file.startsWith(path.join(root,'verification')+path.sep),'run must be verification-local');run=finishRun(root,read(root,o.run),o.report,o.observations);atomic(file,run);}
  console.log(JSON.stringify({status:run.status,output:file,gui_run:false,acceptance_updated:false}));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{runCli(process.argv.slice(2));}catch(e){console.error(e.message);process.exitCode=1;}}
