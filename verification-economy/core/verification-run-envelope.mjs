// Identity capture only: no runner/app launch, clipboard, or PASS marker.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {readJson, planVerification} from './verification-policy.mjs';
import {approvedHostArtifact, observeHostFile, identityDemand} from './executable-provenance.mjs';
const sha = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').toUpperCase();
const check = (ok, message) => {if (!ok) throw new Error(message);};
function owned(root, file) {
  const absolute=path.resolve(root,file); check(absolute.startsWith(path.resolve(root)+path.sep),'envelope reference outside project');return absolute;
}
function freezeCheck(root, file) {
  const entries=readJson(owned(root,file));check(Array.isArray(entries)&&entries.length>0,'empty source freeze');
  for(const e of entries)check(sha(owned(root,e.path))===e.sha256,'source freeze changed');
  return sha(owned(root,file));
}
export function beginEnvelope(root, policy, plan, id, sourceFreeze) {
  check(plan.status==='PLANNED'&&JSON.stringify(planVerification(policy,plan.planning_input))===JSON.stringify(plan),'invalid/current plan required');
  check(plan.selected_scenario_ids.includes(id),'scenario not selected');
  const scenario=policy.scenario_registry.find(s=>s.id===id), file=owned(root,scenario.file), recipe=readJson(file);
  const provenance=approvedHostArtifact(root,policy,scenario,recipe);
  const artifact=provenance?.host.canonical_path??owned(root,recipe.application.command), artifactHash=provenance?.host.sha256??sha(artifact);
  check(!plan.artifact?.sha256||plan.artifact.sha256===artifactHash,'planned artifact mismatch');
  return {schema_version:1,milestone:plan.milestone,policy_digest:plan.policy_digest,scenario_id:id,
    artifact_path:path.relative(root,artifact),recipe_path:scenario.file,source_freeze_path:path.relative(root,owned(root,sourceFreeze)),
    artifact_before:artifactHash,source_freeze_before:freezeCheck(root,sourceFreeze),recipe_sha256:sha(file),
    ...(provenance ? {executable_provenance:{schema:provenance.contract.schema,artifact_id:provenance.contract.artifact_id,host_before:provenance.host}} : {}),
    started_at:new Date().toISOString(),status:'RUNNING',gui_execution:'not performed by this tool'};
}
export function finishEnvelope(root, run, reportFile) {
  check(run.status==='RUNNING'&&!run.completed_at,'run already finalized/not running');
  let hostAfter;
  if(run.executable_provenance){
    hostAfter=observeHostFile(root,run.artifact_path,{elf:true});
    identityDemand(JSON.stringify(hostAfter)===JSON.stringify(run.executable_provenance.host_before),'host artifact identity changed during run');
  }
  const artifactAfter=hostAfter?.sha256??sha(owned(root,run.artifact_path)), sourceAfter=freezeCheck(root,run.source_freeze_path);
  check(artifactAfter===run.artifact_before&&sourceAfter===run.source_freeze_before,'artifact/source changed during run');
  check(sha(owned(root,run.recipe_path))===run.recipe_sha256,'recipe changed during run');
  check(fs.statSync(owned(root,reportFile)).mtimeMs + 1 >= Date.parse(run.started_at),'raw report predates this run; preserve history and use a fresh attempt');
  check(readJson(owned(root,reportFile)).test===readJson(owned(root,run.recipe_path)).name,'raw report is not selected recipe');
  return {...run,artifact_after:artifactAfter,source_freeze_after:sourceAfter,report_path:path.relative(root,owned(root,reportFile)),
    ...(hostAfter ? {executable_provenance:{...run.executable_provenance,host_after:hostAfter}} : {}),
    report_sha256:sha(owned(root,reportFile)),completed_at:new Date().toISOString(),status:'CAPTURED',note:'identity captured, not PASS; verifier still checks complete raw evidence'};
}
export function runEnvelopeCli(args, defaultRoot = process.cwd()) {
  const command=args.shift(), o={};
  for(let i=0;i<args.length;i+=2){check(args[i].startsWith('--')&&args[i+1]!==undefined,'invalid envelope argument');const k=args[i].slice(2);check(!(k in o),'duplicate envelope option');o[k]=args[i+1];}
  const allowed={begin:['root','plan','scenario','source-freeze','output'],finish:['root','run','report']}[command];check(allowed&&Object.keys(o).every(k=>allowed.includes(k)),'unknown envelope option');
  const root=path.resolve(o.root??defaultRoot);
  if(command==='begin'){
    const run=beginEnvelope(root,readJson(path.join(root,'verification/verification-policy.json')),readJson(owned(root,o.plan)),o.scenario,o['source-freeze']), output=owned(root,o.output);
    check(output.startsWith(path.join(root,'verification')+path.sep),'envelope output must be verification-local');
    fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify(run,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({status:run.status,output,gui_run:false}));
  }else{
    const file=owned(root,o.run);check(file.startsWith(path.join(root,'verification')+path.sep),'run must be verification-local');
    const run=finishEnvelope(root,readJson(file),o.report), temp=file+'.'+crypto.randomUUID()+'.tmp';
    try{fs.writeFileSync(temp,JSON.stringify(run,null,2)+'\n',{flag:'wx'});fs.renameSync(temp,file);}finally{if(fs.existsSync(temp))fs.unlinkSync(temp);}
    console.log(JSON.stringify({status:run.status,output:file,acceptance_updated:false}));
  }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{runEnvelopeCli(process.argv.slice(2));}catch(e){console.error(e.message);process.exitCode=1;}}
