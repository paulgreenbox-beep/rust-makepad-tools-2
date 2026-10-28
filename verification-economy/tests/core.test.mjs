import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {bindPolicy,loadProject,planProject,validatePlan,verifyEvidence,recordProject,beginRun,finishRun,resourceAdmission,classifyResult,digest,expectedPostcondition} from '../core/index.mjs';
import {readJson,validatePolicy,planVerification,recordAcceptedMilestone,verifyAcceptanceProof} from '../core/verification-policy.mjs';
const profiles=fileURLToPath(new URL('../profiles/',import.meta.url));
const names=['makepad-windows','makepad-semantic','makepad-linux-wslc','gpu-rendering','scheduler-workers'];
const hash='A'.repeat(64);
function sample(name='makepad-windows',knownCount=0){
  const p=loadProject(path.join(profiles,name));
  if(knownCount!==null){p.milestone_history=[{milestone:'BASE',status:'ACCEPTED',kind:'functional',expanded_gui:true,artifact_hash:hash,date:'2026-10-01'}];for(let n=0;n<knownCount;n++)p.milestone_history.push({milestone:`F-${n}`,status:'ACCEPTED',kind:'functional',expanded_gui:false,artifact_hash:hash,date:'2026-10-02'});p.periodic_regression={...p.periodic_regression,state:'KNOWN',last_full_gui_milestone:'BASE',milestones_since_last_full:knownCount};}
  return p;
}
const input=(module='pure',extra={})=>({milestone_id:'NEXT',changed_modules:[module],...extra});
const allResources={desktop_lease:true,physical_input:true,native_clipboard:true,wslc_session:true,gpu:true,large_build:true,worker_lease:true,available_ram_mib:4096,heavy_workloads_active:0};
for(const name of names)test(`sample ${name}: valid; plan only, NOT_RUN, no consumer history edits`,()=>{
  const root=path.join(profiles,name),p=loadProject(root),before=JSON.stringify(p),plan=planProject(p,input('verification-infrastructure',{kind:'infrastructure'}));
  assert.equal(validatePolicy(p,root).status,'PASS');assert.equal(plan.estimated_gui_runs,0);assert.equal(plan.execution.runs_gui,false);assert.equal(JSON.stringify(p),before);
});
test('pure change uses L0 only below cadence; explanation for every scenario',()=>{const p=sample(),plan=planProject(p,input());assert.equal(plan.estimated_gui_runs,0);assert.equal(plan.required.L0[0].id,'contract-unit');assert.equal(plan.selected_scenario_ids.length+plan.skipped_periodic_tests.length,p.scenario_registry.length);});
test('cross-component dependency impact retains integration gate',()=>{const p=sample();p.dependency_impact=[{owner:'pure',dependents:['windows-ui']}];const plan=planProject(p,input());assert.equal(plan.required.L2[0].id,'launcher-contract');assert.ok(plan.l4b_required);});
test('file-only change expands owning-module dependency impact',()=>{const p=sample();p.dependency_impact=[{owner:'pure',dependents:['windows-ui']}];const plan=planProject(p,{milestone_id:'NEXT',changed_files:['src/pure/helper.rs']});assert.ok(plan.changed_modules.includes('windows-ui'));assert.equal(plan.required.L2[0].id,'launcher-contract');assert.ok(plan.l4b_required);});
test('explicit shared risk selects narrow relevant composition',()=>{const plan=planProject(sample(),input('pure',{risk_override:['window-identity']}));assert.ok(plan.selected_scenario_ids.includes('windows-ui-composition'));assert.ok(!plan.selected_scenario_ids.includes('Office'));});
test('unknown impact requires review, never PASS',()=>assert.equal(planProject(sample(),{milestone_id:'NEXT',changed_files:['unknown.rs']}).status,'NEEDS_IMPACT_REVIEW'));
test('fifth accepted functional closure requires composition without increment on plan',()=>{const p=sample('makepad-windows',4);const plan=planProject(p,input());assert.equal(plan.periodic_counter.due,true);assert.equal(plan.l4b_required,true);assert.equal(p.periodic_regression.milestones_since_last_full,4);});
test('unknown baseline calibrates, never invents count',()=>{const plan=planProject(sample('makepad-windows',null),input());assert.equal(plan.l4b_required,true);assert.equal(plan.periodic_counter.prospective_after_acceptance,null);});
test('narrow risk composition cannot postpone full fifth-milestone cadence',()=>{const p=sample('makepad-windows',3);p.feature_tags.push('narrow');p.risk_triggers.push({id:'narrow-risk',feature_tags:['narrow']});const s=structuredClone(p.scenario_registry.find(s=>s.level==='L4b'));Object.assign(s,{id:'narrow-composition',default_periodic:false,run_when:['narrow'],features_proven:['narrow'],risk_tags:['narrow-risk']});p.scenario_registry.push(s);const plan=planVerification(p,input('pure',{risk_override:['narrow-risk']}));assert.deepEqual(plan.required.L4b.map(s=>s.id),['narrow-composition']);const next=recordAcceptedMilestone(p,{milestone:'NEXT',status:'ACCEPTED',kind:'functional',expanded_gui:true,artifact_hash:hash,date:'2026-10-10',verified_proof:true},plan).policy;assert.equal(next.periodic_regression.milestones_since_last_full,4);assert.equal(next.periodic_regression.last_full_gui_milestone,'BASE');assert.equal(next.milestone_history.at(-1).expanded_gui,false);assert.equal(planProject(next,{milestone_id:'FIFTH',changed_modules:['pure']}).periodic_counter.due,true);});
test('soft budget override retains all required scenarios and reasons',()=>{const p=sample();p.budgets.typical_gui_runs=1;const i=input('windows-ui');const before=planProject(p,i),after=planProject(p,{...i,budget_override_reason:'retain narrow required composition for proven shared risk'});assert.equal(before.status,'BUDGET_JUSTIFICATION_REQUIRED');assert.equal(after.status,'PLANNED');assert.deepEqual(after.selected_scenario_ids,before.selected_scenario_ids);assert.ok(after.budget.override.required_scenarios.length);});
test('missing fixture, quarantine and unexplained flake cannot imply acceptance',()=>{for(const [field,value,status]of [['requires_fixture_review',true,'NEEDS_FIXTURE_REVIEW'],['stability','quarantined','BLOCKED_TEST_INVESTIGATION']]){const p=sample();p.scenario_registry[0][field]=value;assert.equal(planProject(p,input('windows-ui')).status,status);}const p=sample();p.scenario_registry[0].stability='flaky_candidate';assert.ok(planProject(p,input('windows-ui')).risk_triggers.includes('unexplained-gui-flake'));});
test('global/consumer safeguards and unsupported versions fail closed',()=>{for(const mutate of [p=>p.policy_version='99.0.0',p=>p.ownership_rules.unknown_impact_requires_review=false,p=>p.artifact_smoke.exact_bytes_required=false,p=>p.lifecycle.quarantine_is_pass=true,p=>p.periodic_regression.interval=6]){const p=sample();mutate(p);assert.throws(()=>planProject(p,input()));}const raw=readJson(path.join(profiles,'makepad-windows/verification/verification-policy.json'));assert.throws(()=>bindPolicy(raw,{schema_version:1,core_version:'2.0.0'}));});
test('stale consumer policy/plan/global digest rejected',()=>{const p=sample(),plan=planProject(p,input());p.budgets.typical_gui_runs=9;assert.throws(()=>validatePlan(p,plan),/stale/);const p2=sample(),p3=planProject(p2,input());p3.global_policy_digest=hash;assert.throws(()=>validatePlan(p2,p3),/stale/);});
test('WSLC GPU change selects policy+launcher+bounded runtime only; operator RAM guard is 2 GiB',()=>{const p=sample('makepad-linux-wslc');const plan=planProject(p,{milestone_id:'GPU-NEXT',changed_files:['experiments/ai-execution-workspace/gpu_policy.py'],available_resources:{...allResources,available_ram_mib:1700}});assert.deepEqual(plan.required.L0.map(t=>t.id),['gpu-policy-unit']);assert.deepEqual(plan.required.L2.map(t=>t.id),['launcher-contract']);assert.deepEqual(plan.selected_scenario_ids,['bounded-nvidia-runtime']);assert.equal(plan.status,'BLOCKED_ENVIRONMENT');assert.equal(plan.resource_requirements.min_available_ram_mib,2048);assert.ok(plan.skipped_periodic_tests.every(s=>!s.id.includes('office')));});
test('unadmitted desktop/parallel heavy workload is environment, not product',()=>{const r={resources:['wslc_session'],min_available_ram_mib:2048,no_unbudgeted_heavy_parallelism:true};assert.equal(resourceAdmission(r,{...allResources,heavy_workloads_active:1}).status,'BLOCKED_ENVIRONMENT');assert.equal(resourceAdmission(r).status,'NOT_CHECKED');});
test('operator 2 GiB VM guard admits its exact boundary, not one byte below or heavy overlap',()=>{
  const p=sample('makepad-linux-wslc');
  for(const [ram,status] of [[2048-1/1048576,'BLOCKED_ENVIRONMENT'],[2048,'PLANNED'],[2500,'PLANNED']]) {
    const plan=planProject(p,{milestone_id:'RAM-2G',changed_files:['experiments/ai-execution-workspace/gpu_policy.py'],
      available_resources:{...allResources,available_ram_mib:ram}});
    assert.equal(plan.status,status);assert.equal(plan.resource_requirements.min_available_ram_mib,2048);
  }
  const plan=planProject(p,{milestone_id:'RAM-2G-HEAVY',changed_files:['experiments/ai-execution-workspace/gpu_policy.py'],
    available_resources:{...allResources,available_ram_mib:2048,heavy_workloads_active:1}});
  assert.equal(plan.status,'BLOCKED_ENVIRONMENT');
});
test('outcome requires dispatch+postcondition+health+evidence+cleanup; mock/ack never PASS',()=>{const full={action_dispatched:true,postconditions_verified:true,runtime_healthy:true,required_evidence_verified:true,cleanup_verified:true,evidence_origin:'real'};assert.equal(classifyResult(full),'PASS');for(const key of ['action_dispatched','required_evidence_verified','cleanup_verified'])assert.equal(classifyResult({...full,[key]:false}),'NOT_RUN');assert.equal(classifyResult({...full,evidence_origin:'mock'}),'NOT_RUN');assert.equal(classifyResult({...full,desktop_unavailable:true}),'BLOCKED_ENVIRONMENT');});

test('cold-build resource uses the same 2 GiB policy as WSLC with strict boundary and overlap refusal',()=>{
 const p=sample();
 p.test_registry.find(t=>t.id==='contract-unit').resources=['large_build'];
 for(const [ram,status] of [[2048-1/1024,'BLOCKED_ENVIRONMENT'],[2048,'PLANNED'],[2048+1/1024,'PLANNED']]){
  const plan=planProject(p,input('pure',{available_resources:{...allResources,available_ram_mib:ram}}));
  assert.equal(plan.resource_requirements.min_available_ram_mib,2048);assert.equal(plan.status,status);
 }
 const heavy=planProject(p,input('pure',{available_resources:{...allResources,available_ram_mib:2048,heavy_workloads_active:1}}));
 assert.equal(heavy.status,'BLOCKED_ENVIRONMENT');
 const missing=planProject(p,input());assert.equal(missing.resource_admission.status,'NOT_CHECKED');
 for(const ram of [NaN,Infinity,-1,undefined]){
  assert.equal(planProject(p,input('pure',{available_resources:{...allResources,available_ram_mib:ram}})).status,'BLOCKED_ENVIRONMENT');
 }
});
// All following files and observations are synthetic validator fixtures. No app,
// physical input, accepted consumer milestone or real E2E marker is produced.
function fixture(t,profile='makepad-windows',module='windows-ui',prepareRecipe=()=>{}) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'toolkit-economy-'));
  t.after(()=>{assert.ok(root.startsWith(path.join(os.tmpdir(),'toolkit-economy-')));fs.rmSync(root,{recursive:true,force:true});});
  const write=(ref,value)=>{const file=path.join(root,ref);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value));};
  const h=ref=>digest(fs.readFileSync(path.join(root,ref)));
  const raw=readJson(path.join(profiles,profile,'verification/verification-policy.json'));const seed=sample(profile);raw.milestone_history=seed.milestone_history;raw.periodic_regression=seed.periodic_regression;
  const binding=readJson(path.join(profiles,profile,'verification/toolkit-core.json'));
  write('verification/toolkit-core.json',binding);
  write('bin/app.exe','SYNTHETIC fixture bytes, never executable');write('src/owned.rs','synthetic source');write('freeze.json',[{path:'src/owned.rs',sha256:h('src/owned.rs')}]);
  for(const s of raw.scenario_registry){const recipe=readJson(path.join(profiles,profile,s.file));recipe.application.command=path.join(root,'bin/app.exe');prepareRecipe(s,recipe);write(s.file,recipe);}
  write('verification/verification-policy.json',raw);
  const p=loadProject(root),plan=planProject(p,input(module,{artifact:{path:'bin/app.exe',sha256:h('bin/app.exe')},available_resources:allResources}));
  write('quality.json',{artifact:{sha256:h('bin/app.exe')},source_freeze_sha256:h('freeze.json'),completed_at:'2020-01-01T00:00:00Z',gates:['L0','L1','L2'].flatMap(l=>plan.required[l]).map(g=>({id:g.id,exit_code:0}))});
  const proofs=[];
  for(const id of plan.selected_scenario_ids){
    const s=p.scenario_registry.find(v=>v.id===id),recipe=readJson(path.join(root,s.file)),run=beginRun(root,p,plan,id,'freeze.json'),steps=[...(recipe.setup??[]),...recipe.steps,...recipe.teardown];
    const report={test:recipe.name,status:'PASSED',summary:{passed:steps.length,total:steps.length,failed:0,skipped:0},steps:steps.map((s,index)=>({index,step:s.step_id??(index<steps.length-recipe.teardown.length?`step-${index}`:`teardown-${index-(steps.length-recipe.teardown.length)}`),operation:s.op,status:'PASS',response:{result:s.op==='get_runtime_health'?{healthy:true,process_alive:true}:s.op==='get_runtime_stderr'?[]:true}}))};
    const obs={schema_version:2,evidence_origin:'real',producer_kind:'native-runtime-observer',project_id:p.project_id,scenario_id:id,run_id:run.run_id,plan_digest:plan.plan_digest,runtime:{pid:123,namespace:'synthetic-test-fixture',platform:'synthetic',window_id:'synthetic-window',artifact_sha256:h('bin/app.exe'),started_at:run.started_at},health:{healthy:true,process_alive:true,observation_source:'synthetic-health-readback'},available_resources:allResources,gpu:{gpu_actual:'NVIDIA synthetic validator fixture',renderer:'D3D12',gpu_match:true,verification_source:'makepad_runtime_log'},steps:[]};
    for(let i=0;i<steps.length;i++){const correlation=`${run.run_id}:${i}`,file=`evidence/${id}-${i}-state.json`,expected=expectedPostcondition(s,steps[i],i);write(file,{evidence_origin:'real',run_id:run.run_id,correlation_id:correlation,operation:steps[i].op,observation_source:'synthetic-state-readback',actual_state:expected,expected_state:expected});obs.steps.push({index:i,operation:steps[i].op,correlation_id:correlation,action_dispatched:true,postcondition_verified:true,observation_source:'synthetic-state-readback',dispatched_at:run.started_at,observed_at:run.started_at,evidence_path:file,evidence_sha256:h(file)});}
    const cleanupFile=`evidence/${id}-cleanup.json`;write(cleanupFile,{evidence_origin:'real',run_id:run.run_id,orphan_processes:0,stuck_pointer_buttons:0,stuck_modifiers:0,active_input_leases:0,stale_windows:0,leaked_resources:0});
    obs.cleanup={pointer_buttons_released:true,modifiers_released:true,input_leases_released:true,processes_exited:true,windows_closed:true,worker_resources_released:true,evidence_path:cleanupFile,evidence_sha256:h(cleanupFile)};
    const reportFile=`evidence/${id}.json`,observationFile=`evidence/${id}-observations.json`,runFile=`evidence/${id}-run.json`;write(reportFile,report);write(observationFile,obs);
    // Controlled synthetic filesystem clock; never rewrite real report times.
    const fixtureTime=new Date(Math.max(Date.now(),Date.parse(run.started_at)));
    for(const file of [reportFile,observationFile])fs.utimesSync(path.join(root,file),fixtureTime,fixtureTime);
    write(runFile,finishRun(root,run,reportFile,observationFile));proofs.push({id,status:'PASS',artifact_hash:h('bin/app.exe'),report:reportFile,run_manifest:runFile});
  }
  const event={project_id:p.project_id,evidence_version:2,milestone:plan.milestone,status:'ACCEPTED',kind:'functional',expanded_gui:plan.l4b_required,artifact_hash:h('bin/app.exe'),artifact_path:'bin/app.exe',quality_report:'quality.json',source_freeze:'freeze.json',date:'2026-10-10',scenario_results:proofs};
  const mutateObservation=fn=>{const proof=proofs[0],run=readJson(path.join(root,proof.run_manifest)),obs=readJson(path.join(root,run.observation_path));fn(obs);write(run.observation_path,obs);run.observation_sha256=h(run.observation_path);write(proof.run_manifest,run);};
  return {root,p,plan,event,write,h,proofs,mutateObservation};
}

// Expected refusals are synthetic contract fixtures, not native UIA evidence.
function refusalFixture(t,{section='steps',declared=true,declareOnOtherStep=false,expectError='ELEMENT_NOT_ENABLED',status='PASS_EXPECTED_ERROR',response={success:false,error:{code:'ELEMENT_NOT_ENABLED',message:'Synthetic native refusal',hresult:'0x80040200',details:{native_hresult:-2147220992}}}}={}) {
  let refusalIndex;
  const f=fixture(t,'makepad-windows','windows-ui',(scenario,recipe)=>{
    if(scenario.id!=='focused-window')return;
    const step={op:'set_value',id:'synthetic.readonly.height',value:'3.2'};
    if(declared)step.expect_error=expectError;
    if(declareOnOtherStep)recipe.teardown[0].expect_error=expectError;
    if(section==='setup')recipe.setup.push(step);
    else recipe[section].unshift(step);
    refusalIndex=[...recipe.setup,...recipe.steps,...recipe.teardown].indexOf(step);
    scenario.postcondition_contracts=[{index:refusalIndex,operation:step.op,expected_state:{height_m:3,revision:7,mutation_count:0}}];
  });
  const proof=f.proofs.find(p=>p.id==='focused-window'),report=readJson(path.join(f.root,proof.report));
  Object.assign(report.steps[refusalIndex],{status,response:structuredClone(response)});
  f.write(proof.report,report);
  const run=readJson(path.join(f.root,proof.run_manifest));
  run.report_sha256=f.h(proof.report);f.write(proof.run_manifest,run);
  return {...f,refusalIndex,refusalProof:proof};
}
const verifyRaw=f=>verifyAcceptanceProof(f.p,f.event,planVerification(f.p,f.plan.planning_input),f.root);

for(const section of ['setup','steps','teardown'])test(`expected refusal raw step: declared exact error accepted in ${section}; raw HRESULT preserved`,t=>{
  const f=refusalFixture(t,{section}),file=path.join(f.root,f.refusalProof.report),before=fs.readFileSync(file);
  assert.equal(verifyRaw(f).verified_proof,true);
  assert.deepEqual(fs.readFileSync(file),before);
  assert.equal(readJson(file).steps[f.refusalIndex].response.error.hresult,'0x80040200');
});
for(const [name,options]of [
  ['undeclared refusal',{declared:false}],
  ['wrong canonical error',{response:{success:false,error:{code:'UNSUPPORTED_ACTION',hresult:'0x80040200'}}}],
  ['case-mismatched canonical error',{response:{success:false,error:{code:'element_not_enabled'}}}],
  ['successful response with matching error',{response:{success:true,error:{code:'ELEMENT_NOT_ENABLED'}}}],
  ['successful response without error',{response:{success:true,result:true}}],
  ['acknowledgement without explicit failure',{response:{error:{code:'ELEMENT_NOT_ENABLED'}}}],
  ['nonboolean failure flag',{response:{success:0,error:{code:'ELEMENT_NOT_ENABLED'}}}],
  ['missing canonical error',{response:{success:false,error:{hresult:'0x80040200'}}}],
  ['message or HRESULT alone',{response:{success:false,error:{message:'ELEMENT_NOT_ENABLED',hresult:'0x80040200'}}}],
  ['empty expected error',{expectError:'',response:{success:false,error:{code:''}}}],
  ['whitespace expected error',{expectError:' ',response:{success:false,error:{code:' '}}}],
  ['null expected error',{expectError:null,response:{success:false,error:{code:null}}}],
  ['nonstring expected error',{expectError:42,response:{success:false,error:{code:42}}}],
  ['ordinary PASS with declared refusal',{status:'PASS'}],
  ['ordinary successful PASS with declared refusal',{status:'PASS',response:{success:true,result:true}}],
  ['ordinary PASS disguising undeclared error',{declared:false,status:'PASS'}],
  ['error declared on different frozen step',{declared:false,declareOnOtherStep:true}]
])test(`expected refusal raw step rejects ${name}`,t=>{
  const f=refusalFixture(t,options);
  assert.throws(()=>verifyRaw(f),/missing or mismatched recipe step focused-window:/);
});
test('expected refusal raw step rejects declaration changed after recipe freeze',t=>{
  const f=refusalFixture(t),scenario=f.p.scenario_registry.find(s=>s.id===f.refusalProof.id),recipe=readJson(path.join(f.root,scenario.file));
  recipe.steps[0].expect_error='UNSUPPORTED_ACTION';f.write(scenario.file,recipe);
  assert.throws(()=>verifyRaw(f),/run recipe\/report integrity mismatch/);
});
test('expected refusal v2 retains consumer-owned no-mutation readback requirement',t=>{
  const f=refusalFixture(t);
  assert.equal(verifyRaw(f).verified_proof,true);
  assert.equal(verifyEvidence(f.root,f.p,f.event,f.plan).verified_proof,true);
  f.mutateObservation(o=>{
    const step=o.steps[f.refusalIndex],state=readJson(path.join(f.root,step.evidence_path));
    state.actual_state={height_m:3.2,revision:8,mutation_count:1};
    f.write(step.evidence_path,state);step.evidence_sha256=f.h(step.evidence_path);
  });
  assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan),/trusted recipe\/consumer contract/);
});
for(const [name,mutate]of [
  ['missing independent no-mutation readback',step=>{delete step.evidence_path;}],
  ['acknowledgement without verified no-mutation',step=>{step.postcondition_verified=false;}]
])test(`expected refusal v2 rejects ${name}`,t=>{
  const f=refusalFixture(t);
  assert.equal(verifyRaw(f).verified_proof,true);
  f.mutateObservation(o=>mutate(o.steps[f.refusalIndex]));
  assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan),/postcondition evidence missing|dispatch acknowledgement/);
});
test('v2 contract verifies complete synthetic fixture; capture is not PASS',t=>{const f=fixture(t);assert.equal(verifyEvidence(f.root,f.p,f.event,f.plan).verified_proof,true);assert.equal(readJson(path.join(f.root,f.proofs[0].run_manifest)).status,'CAPTURED');});
test('stale artifact and frozen source rejected',t=>{const f=fixture(t);f.write('bin/app.exe','changed');assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan),/artifact/);});
test('unchecked resources refuse begin and acceptance before touching app',t=>{const f=fixture(t),i={...f.plan.planning_input};delete i.available_resources;const plan=planProject(f.p,i);assert.equal(plan.resource_admission.status,'NOT_CHECKED');assert.throws(()=>beginRun(f.root,f.p,plan,f.proofs[0].id,'freeze.json'),/resources must be admitted/);assert.throws(()=>verifyEvidence(f.root,f.p,f.event,plan),/resources not admitted/);});
test('lower-only build resource proof cannot bypass admission without GUI scenarios',t=>{const f=fixture(t,'makepad-windows','pure'),raw=readJson(path.join(f.root,'verification/verification-policy.json'));raw.test_registry[0].resources=['large_build'];f.write('verification/verification-policy.json',raw);const p=loadProject(f.root),plan=planProject(p,input('pure',{artifact:{path:'bin/app.exe',sha256:f.h('bin/app.exe')},available_resources:allResources}));assert.equal(plan.selected_scenario_ids.length,0);assert.throws(()=>verifyEvidence(f.root,p,f.event,plan),/lower-level resource proof/);});
test('rehashed equal null/null readback cannot invent expected postcondition',t=>{const f=fixture(t);f.mutateObservation(o=>{const s=o.steps[0],state=readJson(path.join(f.root,s.evidence_path));state.actual_state=null;state.expected_state=null;f.write(s.evidence_path,state);s.evidence_sha256=f.h(s.evidence_path);});assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan),/trusted recipe\/consumer contract/);});
test('custom action expectations must be consumer-owned, not observer-selected',()=>{assert.throws(()=>expectedPostcondition({}, {op:'click'},0),/missing consumer/);assert.deepEqual(expectedPostcondition({postcondition_contracts:[{index:0,operation:'click',expected_state:{selected:'A'}}]},{op:'click'},0),{selected:'A'});});
test('rehashed runtime starting after all actions/cleanup cannot pass',t=>{const f=fixture(t);f.mutateObservation(o=>o.runtime.started_at='2099-01-01T00:00:00Z');assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan),/runtime identity\/freshness/);});
test('fresh report never hides modified frozen source',t=>{const f=fixture(t);f.write('src/owned.rs','modified');assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan),/source changed/);});
test('unexplained flake blocks v2 acceptance even when required risk selected',()=>{const p=sample();p.scenario_registry[0].stability='flaky_candidate';const plan=planProject(p,input('windows-ui'));assert.equal(plan.status,'BLOCKED_TEST_INVESTIGATION');assert.ok(plan.l4b_required);});
test('exact scenario IDs rejects duplicates/extra/missing reports',t=>{const f=fixture(t);for(const proofs of [f.proofs.slice(1),[...f.proofs,f.proofs[0]],f.proofs.map((p,i)=>i? p:{...p,id:'unrelated'})])assert.throws(()=>verifyEvidence(f.root,f.p,{...f.event,scenario_results:proofs},f.plan),/exact scenario/);});
for(const [name,mutate]of [
  ['mock origin',o=>o.evidence_origin='mock'],['wrong project',o=>o.project_id='other-consumer'],['wrong runtime artifact',o=>o.runtime.artifact_sha256=hash],['missing runtime identity',o=>delete o.runtime.pid],['missing health',o=>o.health.healthy=false],['missing cleanup',o=>delete o.cleanup.input_leases_released],['ack without actual readback',o=>o.steps[0].postcondition_verified=false],['duplicate correlation',o=>o.steps[1].correlation_id=o.steps[0].correlation_id],['old log timestamps',o=>o.steps[0].observed_at='2020-01-01T00:00:00Z'],['blocked desktop',o=>o.available_resources.desktop_lease=false]
])test(`reject ${name} even with a rehashed sidecar`,t=>{const f=fixture(t);f.mutateObservation(mutate);assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan));});
test('cleanup hashes cannot hide leaked resource telemetry',t=>{const f=fixture(t);f.mutateObservation(o=>{const data=readJson(path.join(f.root,o.cleanup.evidence_path));data.leaked_resources=1;f.write(o.cleanup.evidence_path,data);o.cleanup.evidence_sha256=f.h(o.cleanup.evidence_path);});assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan),/cleanup telemetry/);});
test('required GPU mismatch or missing independent observation rejected',t=>{const f=fixture(t,'gpu-rendering','gpu-renderer');f.mutateObservation(o=>o.gpu={gpu_actual:'llvmpipe',renderer:'software',gpu_match:false,verification_source:'environment-variable'});assert.throws(()=>verifyEvidence(f.root,f.p,f.event,f.plan),/GPU/);});
test('consumer isolation: matching module/artifact alone never accepts another project',t=>{const f=fixture(t);const other=sample('makepad-semantic');assert.throws(()=>verifyEvidence(f.root,other,f.event,f.plan),/stale|identity/);});
test('locked atomic updater is idempotent for exact request; conflicting duplicate rejected',t=>{const f=fixture(t);assert.equal(recordProject(f.root,f.event,f.plan).changed,true);const before=fs.readFileSync(path.join(f.root,'verification/verification-policy.json'),'utf8');assert.equal(recordProject(f.root,f.event,f.plan).changed,false);assert.equal(fs.readFileSync(path.join(f.root,'verification/verification-policy.json'),'utf8'),before);assert.throws(()=>recordProject(f.root,{...f.event,date:'2026-10-11'},f.plan),/conflicting/);assert.equal(fs.existsSync(path.join(f.root,'verification/verification-policy.json.acceptance.lock')),false);});
test('held lease/lock refuses update without stealing or deleting it',t=>{const f=fixture(t),lock=path.join(f.root,'verification/verification-policy.json.acceptance.lock');f.write('verification/verification-policy.json.acceptance.lock','owned by other writer');assert.throws(()=>recordProject(f.root,f.event,f.plan),/EEXIST/);assert.equal(fs.readFileSync(lock,'utf8'),'owned by other writer');});
test('PARTIAL/infrastructure attempts do not advance consumer history',t=>{const f=fixture(t);const before=readJson(path.join(f.root,'verification/verification-policy.json'));assert.equal(recordProject(f.root,{...f.event,status:'PARTIAL'},f.plan).changed,false);assert.equal(recordProject(f.root,{...f.event,kind:'infrastructure'},f.plan).changed,false);assert.deepEqual(readJson(path.join(f.root,'verification/verification-policy.json')).milestone_history,before.milestone_history);});
