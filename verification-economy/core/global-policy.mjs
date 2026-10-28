import fs from 'node:fs';
import crypto from 'node:crypto';
export const digest = value => crypto.createHash('sha256').update(Buffer.isBuffer(value) || typeof value==='string' ? value : JSON.stringify(value)).digest('hex').toUpperCase();
export const demand = (ok, message) => {if(!ok) throw new Error(message);};
export function globalPolicy() {return JSON.parse(fs.readFileSync(new URL('./global-policy.json',import.meta.url),'utf8'));}
export function globalDigest() {return digest(globalPolicy());}
export function validateGlobalOverlay(policy) {
  const g=globalPolicy();
  demand(g.schema_version===1 && g.policy_version==='1.0.0','unsupported global policy version');
  demand(g.consumer_schema_versions.includes(policy.schema_version) && g.consumer_policy_versions.includes(policy.policy_version),'unsupported consumer policy version');
  for(const key of g.ownership_safeguards)demand(policy.ownership_rules?.[key]===true,`mandatory safeguard disabled: ${key}`);
  for(const key of g.smoke_safeguards)demand(policy.artifact_smoke?.[key]===true,`mandatory smoke safeguard disabled: ${key}`);
  demand(policy.lifecycle?.quarantine_is_pass===false,'quarantine must not be PASS');
  demand(Number.isSafeInteger(policy.periodic_regression?.interval) && policy.periodic_regression.interval>0 && policy.periodic_regression.interval<=g.periodic_interval,'invalid periodic interval: cannot weaken global cadence');
  demand(Array.isArray(policy.retry_policy?.outcomes) && g.outcomes.every(v=>policy.retry_policy.outcomes.includes(v)),'required retry outcomes missing');
  if(policy.global_policy_version!==undefined)demand(policy.global_policy_version===g.policy_version,'global/consumer version mismatch');
  if(policy.evidence_version!==undefined)demand(policy.evidence_version===2,'unsupported evidence version');
}
