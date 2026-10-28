// Integrated Core evidence contract, not an executor or a second validator.
// Trust boundary: source-pinned native owner produces kernel observations;
// offline verification reopens host bytes and verifies the complete receipt DAG.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const WSLC_EXECUTABLE_PROVENANCE = 'toolkit-wslc-host-guest-executable-provenance-v1';
export const MODULE_SHELL_BUILD_SCHEMA = 'toolkit-linux-module-shell-build-result-v1';
export const MODULE_SHELL_SOURCE_SCHEMA = 'toolkit-trusted-linux-module-shell-build-inputs-v1';
const MAKEPAD71 = '71c9ddcbb9c01dd208f99621fdd71024a5d35c65';
export const MODULE_SHELL_UPSTREAM_INPUTS = Object.freeze([
  'libs/app_module/src/lib.rs', 'apps/wm/src/module_host.rs', 'apps/wm/src/module_view.rs',
  'apps/wm/src/ai_bus.rs', 'apps/wm/src/dylib_host.rs', 'platform/src/storage.rs',
  'widgets/core/src/widget_async.rs', 'libs/app_module/Cargo.toml', 'apps/wm/src/hub.rs',
]);
const text = x => typeof x === 'string' && x.length > 0;
const sha = x => typeof x === 'string' && /^[A-F0-9]{64}$/.test(x);
const hash = x => crypto.createHash('sha256').update(x).digest('hex').toUpperCase();
export function identityDemand(ok, message, code = 'IDENTITY_MISMATCH') {
  if (!ok) { const error = new Error(`${code}: ${message}`); error.code = code; throw error; }
}
const canonical = x => Array.isArray(x) ? x.map(canonical) : x && typeof x === 'object' ? Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])) : x;
const same = (a,b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const nativePath = x => typeof x === 'string' && /^\\\\\?\\[A-Za-z]:\\/.test(x) ? x.slice(4) : x;
const statIdentity = s => Object.fromEntries(['dev','ino','mode','nlink','size','mtimeNs','ctimeNs'].map(k => [k,String(s[k])]));

export function provenancePath(root, ref) {
  identityDemand(text(ref) && !ref.split(/[\\/]/).includes('..'), 'unsafe provenance path');
  const base = path.resolve(root), file = path.resolve(base,nativePath(ref));
  identityDemand(file.startsWith(base + path.sep), 'provenance path escapes project');
  // Inspect all ancestors, not just realpath(final). Junctions/reparse-backed
  // aliases and symlink substitution must not become trusted artifact storage.
  for (let p = file; p !== path.dirname(p); p = path.dirname(p)) {
    const s = fs.lstatSync(p);
    identityDemand(!s.isSymbolicLink() && path.resolve(fs.realpathSync(p)).toLowerCase() === path.resolve(p).toLowerCase(), 'provenance reparse/symlink refused');
  }
  return file;
}

export function observeHostFile(root, ref, {elf = false, limit = 512 * 1024 * 1024, capture = false} = {}) {
  let fd;
  try {
    const file = provenancePath(root,ref), before = fs.lstatSync(file,{bigint:true});
    identityDemand(before.isFile() && before.nlink === 1n && before.size > 0n && before.size <= BigInt(limit), 'nonregular, linked or unbounded host artifact');
    fd = fs.openSync(file,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const opened = fs.fstatSync(fd,{bigint:true});
    identityDemand(same(statIdentity(before),statIdentity(opened)), 'host path/open FD changed');
    const digest = crypto.createHash('sha256'), chunk = Buffer.alloc(1024 * 1024);
    let count = 0, magic; const chunks = [];
    for (;;) {
      const n = fs.readSync(fd,chunk,0,chunk.length,null);
      if (!n) break;
      if (!count) magic = Buffer.from(chunk.subarray(0,4));
      count += n; identityDemand(count <= limit,'host read bound exceeded'); digest.update(chunk.subarray(0,n));
      if (capture) chunks.push(Buffer.from(chunk.subarray(0,n)));
    }
    const after = fs.fstatSync(fd,{bigint:true}), final = fs.lstatSync(provenancePath(root,ref),{bigint:true});
    identityDemand(same(statIdentity(opened),statIdentity(after)) && same(statIdentity(after),statIdentity(final)) && BigInt(count) === opened.size, 'host file changed while hashing');
    identityDemand(!elf || magic?.equals(Buffer.from([0x7f,0x45,0x4c,0x46])), 'host payload is not ELF');
    return {canonical_path:file,sha256:digest.digest('hex').toUpperCase(),bytes:count,file_identity:statIdentity(after),...(capture ? {content:Buffer.concat(chunks,count)} : {})};
  } catch (error) {
    if (error.code?.startsWith('IDENTITY_')) throw error;
    identityDemand(false,`host observation failed: ${error.code ?? error.name}`,'IDENTITY_NOT_VERIFIED');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

export function parseIdentityJson(bytes) {
  try {
    const raw = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    // JSON.parse validates syntax; this second lexical walk rejects duplicate
    // keys (including differently escaped spellings) without a lossy reviver.
    const value = JSON.parse(raw);
    const tokens = raw.match(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g) ?? [];
    let i = 0;
    function walk(depth) {
      identityDemand(depth <= 64,'JSON nesting bound','IDENTITY_NOT_VERIFIED');
      const token = tokens[i++];
      if (token === '{') {
        const keys = new Set();
        if (tokens[i] === '}') {i++;return;}
        for (;;) {
          const key = JSON.parse(tokens[i++]);
          identityDemand(typeof key === 'string' && !keys.has(key),'duplicate identity JSON key','IDENTITY_NOT_VERIFIED'); keys.add(key);
          identityDemand(tokens[i++] === ':','invalid identity JSON','IDENTITY_NOT_VERIFIED'); walk(depth+1);
          const end = tokens[i++]; if (end === '}') break;
          identityDemand(end === ',','invalid identity JSON','IDENTITY_NOT_VERIFIED');
        }
      } else if (token === '[') {
        if (tokens[i] === ']') {i++;return;}
        for (;;) {walk(depth+1);const end=tokens[i++];if(end===']')break;identityDemand(end===',','invalid identity JSON','IDENTITY_NOT_VERIFIED');}
      } else identityDemand(token !== undefined && !['}',']',':',','].includes(token),'invalid identity JSON','IDENTITY_NOT_VERIFIED');
    }
    walk(0);identityDemand(i === tokens.length,'trailing identity JSON','IDENTITY_NOT_VERIFIED');
    return value;
  } catch (error) {
    if (error.code?.startsWith('IDENTITY_')) throw error;
    identityDemand(false,'invalid/truncated/UTF-8 identity JSON','IDENTITY_NOT_VERIFIED');
  }
}

export function readProvenanceRef(root, ref) {
  identityDemand(text(ref?.path) && sha(ref?.sha256), 'missing immutable receipt reference','IDENTITY_NOT_VERIFIED');
  const observed = observeHostFile(root,ref.path,{limit:8*1024*1024,capture:true});
  identityDemand(observed.sha256 === ref.sha256,'receipt byte digest mismatch');
  return parseIdentityJson(observed.content);
}

// ModuleShell is an explicit producer-shape extension, not another provenance
// authority. All container/transfer/kernel/session verification below remains
// shared. Paths in this contract are consumer-root relative host archive refs;
// Linux paths describe actual compiled/staged files, never host read authority.
//
// source manifest:
// {schema, profile_kind:'ModuleShell', source_commit, files:[{path,sha256,bytes}],
//  upstream:{linux_root,files:[{relative_path,path,sha256,bytes}]},
//  compiled:{linux_root,target_dir,cargo_manifest,cargo_lock,
//            rust_sources:[{relative_path,path,sha256,bytes}]},
//  transformations:[{kind:'cargo-paths'|'module-host-path',input,output,
//                    replacements:[{from,to,count}]}], harness,operator_plan}
// input/output/harness/operator_plan are {path,sha256,bytes} refs in files.
// build receipt:
// {schema,profile_kind,exit_code:0,timed_out:false,output_drained:true,receipt,
//  source:{SDK_pin,source_manifest_sha256},before:files,after:files,
//  toolchain:{target:'x86_64-unknown-linux-gnu',rustc_vv,cargo_version},
//  cargo:{args:[...]},artifact:{sha256,bytes,actual_compiler_artifact}}
// Native stdout must contain exactly one JSON marker for each of BEFORE,
// AFTER, TOOLCHAIN, COMMAND, ARTIFACT (see shellMarker), actual Cargo JSON and
// the ordinary sha256sum line. The trusted harness itself is hashed/reopened.
function shellMarker(native, name, expected) {
  const prefix = `TOOLKIT_MODULE_SHELL_${name} `;
  const lines = native.stdout.split(/\r?\n/).filter(line=>line.startsWith(prefix));
  identityDemand(lines.length === 1 && same(parseIdentityJson(Buffer.from(lines[0].slice(prefix.length))),expected),`ModuleShell actual ${name} observation missing/mismatch`);
  return native.stdout.split(/\r?\n/).findIndex(line=>line.startsWith(prefix));
}
const shellLinuxPath = value => text(value) && value.startsWith('/') && value.length > 1 && !/[\\\s\x00-\x1f]/.test(value) && !value.slice(1).split('/').some(part=>part==='.'||part==='..'||part==='');

function moduleShellBuild(root, c, profile, build, sources) {
  identityDemand(profile.module_shell?.source_manifest_sha256 === c.source_manifest.sha256,'ModuleShell source set not approved by trusted profile');
  identityDemand(build.schema === MODULE_SHELL_BUILD_SCHEMA && build.profile_kind === 'ModuleShell' && build.exit_code === 0 && build.timed_out === false && build.output_drained === true && build.source?.SDK_pin === MAKEPAD71 && build.source.source_manifest_sha256 === c.source_manifest.sha256,'ModuleShell source-bound build receipt mismatch');
  identityDemand(build.artifact?.sha256 === c.sha256 && build.artifact?.bytes === c.bytes,'ModuleShell compiled ELF digest/length mismatch');
  identityDemand(sources.schema === MODULE_SHELL_SOURCE_SCHEMA && sources.profile_kind === 'ModuleShell' && sources.source_commit === MAKEPAD71 && Array.isArray(sources.files) && sources.files.length > 0 && sources.files.length <= 512,'ModuleShell bounded input manifest missing');
  const entries = new Map(); let capturedBytes = 0;
  for (const entry of sources.files) {
    identityDemand(text(entry?.path) && sha(entry.sha256) && Number.isSafeInteger(entry.bytes) && entry.bytes > 0,'ModuleShell incomplete file pin');
    const observed = observeHostFile(root,entry.path,{limit:8*1024*1024,capture:true});
    capturedBytes += observed.bytes;
    identityDemand(capturedBytes <= 64*1024*1024,'ModuleShell archived source byte budget exceeded');
    identityDemand(!entries.has(observed.canonical_path) && observed.sha256 === entry.sha256 && observed.bytes === entry.bytes,'ModuleShell actual input bytes changed/duplicated');
    entries.set(observed.canonical_path,{entry,observed});
  }
  const input = ref => {
    identityDemand(text(ref?.path) && sha(ref.sha256) && Number.isSafeInteger(ref.bytes),'ModuleShell input ref missing','IDENTITY_NOT_VERIFIED');
    const value = entries.get(provenancePath(root,ref.path));
    identityDemand(value && same(value.entry,{path:ref.path,sha256:ref.sha256,bytes:ref.bytes}),'ModuleShell input not in exact archived source set');
    return value.observed;
  };
  identityDemand(same(build.before,sources.files) && same(build.after,sources.files),'ModuleShell before/after source drift');
  const up = sources.upstream, compiled = sources.compiled;
  identityDemand(shellLinuxPath(up?.linux_root) && Array.isArray(up.files) && up.files.length >= MODULE_SHELL_UPSTREAM_INPUTS.length && up.files.length <= 128,'ModuleShell upstream source roots missing');
  const upstream = new Map();
  for(const entry of up.files) {
    identityDemand(text(entry.relative_path) && !entry.relative_path.startsWith('/') && !/[\\]/.test(entry.relative_path) && !entry.relative_path.split('/').some(s=>!s||s==='.'||s==='..') && !upstream.has(entry.relative_path),'ModuleShell upstream path invalid/duplicated');
    input({path:entry.path,sha256:entry.sha256,bytes:entry.bytes}); upstream.set(entry.relative_path,entry);
  }
  for(const relative of MODULE_SHELL_UPSTREAM_INPUTS) identityDemand(upstream.has(relative),`ModuleShell required pinned input omitted: ${relative}`);
  identityDemand(shellLinuxPath(compiled?.linux_root) && shellLinuxPath(compiled.target_dir) && Array.isArray(compiled.rust_sources) && compiled.rust_sources.length > 0 && compiled.rust_sources.length <= 128,'ModuleShell compiled source map missing');
  input(compiled.cargo_manifest); input(compiled.cargo_lock);
  const rust = new Map();
  for(const ref of compiled.rust_sources) {
    identityDemand(/^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\.rs$/.test(ref.relative_path ?? '') && !rust.has(ref.relative_path),'ModuleShell compiled Rust path invalid/duplicated');
    input({path:ref.path,sha256:ref.sha256,bytes:ref.bytes});rust.set(ref.relative_path,ref);
  }
  for(const name of ['src/main.rs','src/lib.rs','src/fixtures.rs','src/tile.rs']) identityDemand(rust.has(name),`ModuleShell required compiled source omitted: ${name}`);
  input(sources.operator_plan);
  const harness = input(sources.harness).content.toString('utf8');
  identityDemand(Array.isArray(sources.transformations) && sources.transformations.length === 2,'ModuleShell path transformations missing');
  const transformed = new Set();
  for(const transform of sources.transformations) {
    identityDemand(['cargo-paths','module-host-path'].includes(transform.kind) && !transformed.has(transform.kind),'ModuleShell unknown/duplicate transform');transformed.add(transform.kind);
    const original = input(transform.input), staged = input(transform.output);
    const expected = transform.kind === 'cargo-paths' ? compiled.cargo_manifest : rust.get('src/main.rs');
    identityDemand(transform.output.path === expected.path && transform.input.path !== transform.output.path && Array.isArray(transform.replacements) && transform.replacements.length > 0 && transform.replacements.length <= 32,'ModuleShell transformed output mapping mismatch');
    let bytes;
    try { bytes = new TextDecoder('utf-8',{fatal:true}).decode(original.content); }
    catch { identityDemand(false,'ModuleShell transformed source is invalid UTF-8','IDENTITY_NOT_VERIFIED'); }
    for(const replacement of transform.replacements) {
      identityDemand(text(replacement.from) && text(replacement.to) && Number.isSafeInteger(replacement.count) && replacement.count > 0 && replacement.count <= 32,'ModuleShell substitution invalid');
      let from, to;
      if(transform.kind === 'module-host-path') {
        from = '#[path = "../../../reports/evidence/makepad-dev-capability-audit-20261015/upstream/apps/wm/src/module_host.rs"]';
        to = `#[path = "${up.linux_root}/apps/wm/src/module_host.rs"]`;
        identityDemand(transform.replacements.length === 1 && replacement.count === 1,'ModuleShell module-host transform must be singular');
      } else {
        const match = /^path = "\.\.\/\.\.\/reports\/evidence\/makepad-dev-capability-audit-20261015\/upstream\/([A-Za-z0-9_/-]+)"$/.exec(replacement.from);
        identityDemand(match && !match[1].split('/').includes('..'),'ModuleShell Cargo transform is not an approved upstream path');
        from = replacement.from; to = `path = "${up.linux_root}/${match[1]}"`;
      }
      identityDemand(replacement.from === from && replacement.to === to && bytes.split(from).length-1 === replacement.count,'ModuleShell source path substitution mismatch');
      bytes = bytes.split(from).join(to);
    }
    identityDemand(Buffer.from(bytes).equals(staged.content),'ModuleShell staged source differs beyond approved path substitutions');
  }
  const main = input({path:rust.get('src/main.rs').path,sha256:rust.get('src/main.rs').sha256,bytes:rust.get('src/main.rs').bytes}).content.toString('utf8');
  const cargoManifest = input(compiled.cargo_manifest).content.toString('utf8');
  identityDemand(main.includes(`#[path = "${up.linux_root}/apps/wm/src/module_host.rs"]`) && !cargoManifest.includes('../../reports/evidence/') && cargoManifest.includes('name = "toolkit-app-module-shell"'),'ModuleShell staged main/Cargo path binding incomplete');
  const tc = build.toolchain;
  identityDemand(tc?.target === 'x86_64-unknown-linux-gnu' && /^rustc [^\n]+\n/.test(tc.rustc_vv ?? '') && /^commit-hash: [a-f0-9]{40}$/m.test(tc.rustc_vv) && /^host: [^\s]+$/m.test(tc.rustc_vv) && /^cargo \d+\.\d+\.\d+/.test(tc.cargo_version ?? ''),'ModuleShell toolchain/target observation missing');
  const args = ['build','--manifest-path',`${compiled.linux_root}/Cargo.toml`,'--bin','toolkit-app-module-shell','--locked','--offline','-j','1','--target',tc.target,'--target-dir',compiled.target_dir,'--message-format=json-render-diagnostics'];
  identityDemand(same(build.cargo?.args,args),'ModuleShell Cargo must be exact locked/offline sequential invocation');
  const native = readProvenanceRef(root,c.native_build_receipt);
  identityDemand(native.exit_code === 0 && native.timed_out === false && native.output_drained === true && typeof native.stdout === 'string','ModuleShell native compiler receipt missing');
  identityDemand(text(build.receipt) && path.resolve(path.dirname(provenancePath(root,c.build_receipt.path)),build.receipt) === provenancePath(root,c.native_build_receipt.path),'ModuleShell build/native receipt join mismatch');
  const script = provenancePath(root,sources.harness.path).replaceAll('\\','/');
  const mountedScript = process.platform === 'win32' ? `/mnt/${script[0].toLowerCase()}${script.slice(2)}` : script;
  identityDemand(native.executable?.replaceAll('\\','/').toLowerCase() === 'c:/windows/system32/wsl.exe' && same(native.args,['-d','Ubuntu','--exec','/bin/bash',mountedScript]),'ModuleShell actual build harness invocation mismatch');
  for(const entry of sources.files.filter(e=>e.path !== sources.harness.path)) identityDemand(harness.includes(entry.sha256) || harness.includes(entry.sha256.toLowerCase()),'ModuleShell harness omits source input pin');
  const markerOrder = Object.fromEntries([['BEFORE',build.before],['AFTER',build.after],['TOOLCHAIN',tc],['COMMAND',args],['ARTIFACT',build.artifact]].map(([name,value])=>[name,shellMarker(native,name,value)]));
  const lines = native.stdout.split(/\r?\n/), executable = build.artifact.actual_compiler_artifact;
  const cargo = lines.filter(l=>l.startsWith('{')).flatMap(l=>{try{return [parseIdentityJson(Buffer.from(l))];}catch{return [];}});
  identityDemand(executable === `${compiled.target_dir}/${tc.target}/debug/toolkit-app-module-shell` && cargo.some(x=>x.reason === 'compiler-artifact' && x.executable === executable && x.target?.name === 'toolkit-app-module-shell' && same(x.target?.kind,['bin']) && x.target?.src_path === `${compiled.linux_root}/src/main.rs`) && cargo.some(x=>x.reason === 'build-finished' && x.success === true) && lines.some(l=>l.toUpperCase() === `${c.sha256}  ${executable}`.toUpperCase()),'ModuleShell actual compiled ELF/source receipt join missing');
  const actualCompilerLine = lines.findIndex(line=>{
    try { const x=parseIdentityJson(Buffer.from(line));return x.reason==='compiler-artifact' && x.executable===executable; }
    catch { return false; }
  });
  const finished = cargo.filter(x=>x.reason==='build-finished');
  const finishedLine = lines.findIndex(line=>{
    try { const x=parseIdentityJson(Buffer.from(line));return x.reason==='build-finished'; }
    catch { return false; }
  });
  identityDemand(finished.length === 1 && finished[0].success === true && markerOrder.BEFORE < markerOrder.COMMAND && markerOrder.TOOLCHAIN < markerOrder.COMMAND && markerOrder.COMMAND < actualCompilerLine && actualCompilerLine < finishedLine && finishedLine < markerOrder.AFTER && markerOrder.AFTER < markerOrder.ARTIFACT,'ModuleShell native build observation order mismatch');
}

export function approvedHostArtifact(root, policy, scenario, recipe) {
  const c = scenario.executable_provenance;
  if (!c) {
    identityDemand(policy.execution_profile !== 'makepad-linux-wslc','WSLC host/guest provenance mapping missing','IDENTITY_NOT_VERIFIED');
    return null;
  }
  identityDemand(policy.evidence_version === 2 && policy.execution_profile === 'makepad-linux-wslc' && c.schema === WSLC_EXECUTABLE_PROVENANCE,'unsupported provenance contract/profile');
  identityDemand(text(c.artifact_id) && sha(c.sha256) && Number.isSafeInteger(c.bytes) && c.bytes > 0,'invalid approved host artifact');
  identityDemand(typeof c.guest_path === 'string' && /^\/(?:[^/\\\s]+\/)*[^/\\\s]+$/.test(c.guest_path) && !c.guest_path.split('/').some(p=>p==='.'||p==='..') && recipe.application.command === c.guest_path,'guest command differs from approved mapping');
  const host = observeHostFile(root,c.host_path,{elf:true});
  identityDemand(host.sha256 === c.sha256 && host.bytes === c.bytes,'approved host bytes changed');
  const profile = readProvenanceRef(root,c.profile), build = readProvenanceRef(root,c.build_receipt), sources = readProvenanceRef(root,c.source_manifest);
  identityDemand(profile.schema === 'toolkit-makepad-remote-wslc-trusted-profile-v1' && profile.experimental_opt_in === true && profile.source_commit === '71c9ddcbb9c01dd208f99621fdd71024a5d35c65' && text(profile.owner),'untrusted WSLC profile');
  identityDemand(profile.expected_identity?.executable === c.guest_path && profile.expected_identity?.executable_sha256?.toUpperCase() === c.sha256,'profile artifact mismatch');
  if (profile.profile_kind === 'ModuleShell') {
    moduleShellBuild(root,c,profile,build,sources);
  } else {
  identityDemand(profile.profile_kind === undefined || profile.profile_kind === 'FocusFixture','unknown approved artifact profile kind');
  identityDemand(build.schema === 'toolkit-linux-focus-fixture-build-result-v1' && build.exit_code === 0 && build.timed_out === false && build.output_drained === true && build.artifact?.sha256 === c.sha256 && build.artifact?.bytes === c.bytes && build.source?.SDK_pin === profile.source_commit,'source-bound artifact build receipt mismatch');
  identityDemand(sources.schema === 'toolkit-trusted-linux-fixture-build-inputs-v1' && Array.isArray(sources.files) && sources.files.length > 0,'source-bound input manifest missing');
  for (const entry of sources.files) identityDemand(observeHostFile(root,entry.path,{limit:8*1024*1024}).sha256 === entry.sha256,'archived build input changed');
  const buildDir = path.dirname(provenancePath(root,c.build_receipt.path));
  const sourceEntry = suffix => sources.files.find(e=>path.resolve(root,e.path) === path.join(buildDir,suffix));
  for (const [name,pin] of [['fixture/src/main.rs',build.source.portable_main_sha256],['fixture/src/focus_trace.rs',build.source.portable_trace_sha256],['fixture/Cargo.lock',build.source.fixture_lock_unchanged]]) identityDemand(sha(pin) && sourceEntry(name)?.sha256 === pin,'compiled source/archive join mismatch');
  identityDemand(sourceEntry('fixture/Cargo.toml') && sourceEntry('operator-plan.json') && sourceEntry('build-focus-fixture.sh'),'build manifest/harness archive omitted');
  const native = readProvenanceRef(root,c.native_build_receipt);
  identityDemand(native.exit_code === 0 && native.timed_out === false && native.output_drained === true && typeof native.stdout === 'string','native compiler receipt missing');
  identityDemand(path.resolve(path.dirname(provenancePath(root,c.build_receipt.path)),build.receipt) === provenancePath(root,c.native_build_receipt.path),'build/native receipt join mismatch');
  const script = provenancePath(root,sourceEntry('build-focus-fixture.sh').path).replaceAll('\\','/');
  const mountedScript = process.platform === 'win32' ? `/mnt/${script[0].toLowerCase()}${script.slice(2)}` : script;
  identityDemand(native.executable?.replaceAll('\\','/').toLowerCase() === 'c:/windows/system32/wsl.exe' && same(native.args,['-d','Ubuntu','--exec','/bin/bash',mountedScript]),'actual build harness invocation mismatch');
  const harness = observeHostFile(root,sourceEntry('build-focus-fixture.sh').path,{limit:65536,capture:true}).content.toString('utf8');
  for (const name of ['fixture/Cargo.toml','fixture/Cargo.lock','fixture/src/main.rs','fixture/src/focus_trace.rs']) identityDemand(harness.includes(sourceEntry(name).sha256.toLowerCase()) || harness.includes(sourceEntry(name).sha256),'build harness omits compiled input pin');
  const lines = native.stdout.split(/\r?\n/), executable = build.artifact.actual_compiler_artifact;
  const cargo = lines.filter(l=>l.startsWith('{')).flatMap(l=>{try{return [JSON.parse(l)];}catch{return [];}});
  identityDemand(text(executable) && cargo.some(x=>x.reason==='compiler-artifact' && x.executable===executable) && cargo.some(x=>x.reason==='build-finished' && x.success===true) && lines.some(l=>l.toUpperCase()===`${c.sha256}  ${executable}`.toUpperCase()),'actual compiled ELF/source receipt join missing');
  }
  const producer = observeHostFile(root,c.producer?.path,{limit:8*1024*1024});
  identityDemand(producer.sha256 === c.producer?.sha256 && profile.helper_sha256?.toUpperCase() === producer.sha256,'trusted owner producer mismatch');
  return {contract:c,host,profile};
}

function procIdentity(raw) {
  identityDemand(text(raw),'missing /proc stat','IDENTITY_NOT_VERIFIED');
  const end = raw.lastIndexOf(')'), fields = raw.slice(end+1).trim().split(/\s+/), pid = Number(raw.slice(0,raw.indexOf('(')).trim());
  identityDemand(end > 0 && Number.isSafeInteger(pid) && pid > 0 && fields.length >= 20 && /^[1-9][0-9]*$/.test(fields[19]) && !['Z','X'].includes(fields[0]),'invalid/dead process observation','OUTCOME_UNKNOWN');
  return {pid,parent:Number(fields[1]),birth:fields[19]};
}
function kernelFile(s) {
  identityDemand(s && ['dev','inode','size','nlink','ctime_ns'].every(k=>typeof s[k]==='string' && /^\d+$/.test(s[k])),'missing kernel file identity','IDENTITY_NOT_VERIFIED');
  identityDemand(s.nlink === '1' && BigInt(s.size) > 0n && BigInt(s.inode) > 0n,'linked/nonregular executable refused');
  return ['dev','inode','size','nlink','ctime_ns'].map(k=>s[k]).join(':');
}
const ms = value => { const n = Date.parse(value); identityDemand(Number.isFinite(n),'missing observation time','IDENTITY_NOT_VERIFIED'); return n; };

// Called only from the existing real Core v2 verifyEvidence path. A JSON
// self-consistency check is not enough: host/source/build/profile bytes above
// and all original owner/transfer/kernel receipts below are reopened by digest.
export function verifyWslcExecutableProvenance(root, policy, scenario, recipe, event, run, obs) {
  const approved = approvedHostArtifact(root,policy,scenario,recipe);
  if (!approved) {
    identityDemand(!obs.runtime?.executable_provenance && !/wslc/i.test(obs.runtime?.platform ?? ''),'WSLC observation without trusted profile mapping','IDENTITY_NOT_VERIFIED');
    return;
  }
  const {contract:c,host,profile} = approved;
  identityDemand(run.executable_provenance?.schema === c.schema && run.executable_provenance.artifact_id === c.artifact_id && same(run.executable_provenance.host_before,host) && same(run.executable_provenance.host_after,host),'host file ownership/identity changed between approval and acceptance');
  identityDemand(Array.isArray(obs.raw_provenance) && obs.raw_provenance.length > 0 && obs.raw_provenance.length <= 2048,'missing WSLC raw evidence index','IDENTITY_NOT_VERIFIED');
  const rawPaths = new Set();
  for(const ref of obs.raw_provenance){
    identityDemand(text(ref?.path) && sha(ref?.sha256),'invalid WSLC raw evidence reference','IDENTITY_NOT_VERIFIED');
    const raw = observeHostFile(root,ref.path,{limit:32*1024*1024});
    identityDemand(!rawPaths.has(raw.canonical_path) && raw.sha256 === ref.sha256,'raw producer evidence changed or duplicated');rawPaths.add(raw.canonical_path);
  }
  for(const ref of [run.report_path,obs.runtime.executable_provenance?.path,...(obs.captures??[]).map(c=>c.evidence_path)]) identityDemand(rawPaths.has(provenancePath(root,ref)),'required original evidence absent from raw index','IDENTITY_NOT_VERIFIED');
  identityDemand(event.artifact_hash === host.sha256 && provenancePath(root,event.artifact_path) === host.canonical_path,'event artifact mapping mismatch');
  const freeze = parseIdentityJson(observeHostFile(root,event.source_freeze,{limit:8*1024*1024,capture:true}).content);
  for (const ref of [c.profile,c.build_receipt,c.native_build_receipt,c.source_manifest,c.producer]) identityDemand(freeze.some(f=>path.resolve(root,f.path)===provenancePath(root,ref.path) && f.sha256===ref.sha256),'provenance dependency not source frozen');
  const witness = readProvenanceRef(root,obs.runtime.executable_provenance);
  identityDemand(witness.schema === 'toolkit-wslc-running-executable-witness-v1','missing running executable witness','IDENTITY_NOT_VERIFIED');
  identityDemand(witness.source_commit === profile.source_commit && witness.owner === profile.owner && witness.owner === obs.runtime.owner && witness.session_id === (obs.runtime.session_id ?? obs.runtime.SessionId) && Number.isSafeInteger(witness.generation) && witness.generation > 0 && witness.generation === obs.runtime.session_generation,'cross-session/owner/generation mismatch');
  identityDemand(same(witness.helper,c.producer),'kernel observer differs from frozen helper');
  const cfg = readProvenanceRef(root,witness.owner_config), ctx = readProvenanceRef(root,witness.context), creator = readProvenanceRef(root,witness.creator_receipt), transfer = readProvenanceRef(root,witness.transfer_receipt);
  const expected = profile.expected_identity, container = witness.container;
  identityDemand(/^[a-f0-9]{64}$/.test(expected.container_id) && /^sha256:[a-f0-9]{64}$/.test(expected.image_id),'invalid approved container/image');
  identityDemand(container?.container_id === expected.container_id && container.image_id === expected.image_id && container.owner === witness.owner && /^[a-f0-9]{32}$/.test(container.nonce ?? ''),'container ownership identity mismatch');
  identityDemand(ctx.container_id === container.container_id && ctx.image === container.image_id && ctx.exclusive_owner === container.owner && ctx.exclusive_nonce === container.nonce && ctx.container_created === container.created && ctx.container_started_at === container.started_at && ctx.owns_container === true && ctx.owns_vm === false && ctx.resumable === false && ctx.source_revision === profile.source_commit,'container incarnation mismatch');
  // Only the source/build/ELF-approved trusted profile selects this extension.
  // Observed memory or a context claiming ModuleShell never selects 2 GiB.
  const moduleShell = profile.profile_kind === 'ModuleShell';
  const memoryMax = moduleShell ? 2147483648 : 1073741824;
  const moduleEnvironment = {
    MAKEPAD_HOME:'/tmp/toolkit-module-shell-wslc-home',
    TOOLKIT_MODULE_PROJECT_ID:'module-shell-wslc-v1',
    TOOLKIT_NATIVE_LATE_PROBE:'1',
  };
  if (moduleShell) {
    identityDemand(ctx.wslc_profile === 'wslc_multi_module' && ctx.module_shell_profile_kind === 'ModuleShell' && ctx.module_shell_source_manifest_sha256 === c.source_manifest.sha256 && ctx.module_shell_source_manifest_sha256 === profile.module_shell.source_manifest_sha256,'ModuleShell trusted resource profile/source join mismatch');
    identityDemand(ctx.memory_max === memoryMax && ctx.cpus === 1 && ctx.module_instances === 2,'ModuleShell exact context resource limits mismatch');
    identityDemand(cfg.profile_kind === 'ModuleShell' && cfg.module_shell?.source_manifest_sha256 === c.source_manifest.sha256,'ModuleShell owner configuration/source join mismatch');
    identityDemand(ctx.module_shell_makepad_home === moduleEnvironment.MAKEPAD_HOME && ctx.module_shell_project_id === moduleEnvironment.TOOLKIT_MODULE_PROJECT_ID && ctx.module_shell_native_late_probe === moduleEnvironment.TOOLKIT_NATIVE_LATE_PROBE,'ModuleShell context environment mismatch');
  }
  const envArgs = moduleShell ? Object.entries(moduleEnvironment).flatMap(([key,value])=>['--env',`${key}=${value}`]) : [];
  const createArgs = ['run','--detach','--rm','--name','aiui-workspace-20261008','--memory',moduleShell ? '2G' : '1G','--cpus','1','--gpus','all',...envArgs,'--label',`aiui.toolkit.owner=${container.owner}`,'--label',`aiui.toolkit.nonce=${container.nonce}`,container.image_id,'sleep','1800'];
  identityDemand(creator.exit_code === 0 && creator.timed_out === false && creator.output_drained === true && creator.stdout?.trim() === container.container_id && same(creator.args,createArgs),'exact owned creator receipt mismatch');
  identityDemand(cfg.owner === witness.owner && cfg.source_commit === profile.source_commit && cfg.session_id === witness.session_id && cfg.generation === witness.generation && same(cfg.expected_identity,expected) && path.resolve(nativePath(cfg.runtime_directory)) === path.resolve(nativePath(profile.runtime_directory)),'owner configuration/session binding mismatch');
  const t = transfer.provenance;
  identityDemand(t?.schema === 'toolkit-wslc-artifact-transfer-provenance-v1' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(t.operation_id ?? ''),'missing exact transfer operation','IDENTITY_NOT_VERIFIED');
  identityDemand(same(t.container,container) && same(t.context,witness.context) && same(t.creator_receipt,witness.creator_receipt),'transfer reused for another container/owner incarnation');
  const inspected = readProvenanceRef(root,t.container_inspect_receipt);
  let actual;
  try { actual = parseIdentityJson(Buffer.from(inspected.stdout)); } catch { identityDemand(false,'invalid actual container inspection','IDENTITY_NOT_VERIFIED'); }
  identityDemand(inspected.exit_code === 0 && inspected.timed_out === false && inspected.output_drained === true && Array.isArray(actual) && actual.length === 1,'partial container observation','IDENTITY_NOT_VERIFIED');
  actual = actual[0];
  identityDemand(!Object.hasOwn(actual.HostConfig ?? {},'Privileged') || actual.HostConfig.Privileged === false,'explicit privileged/unknown container mode refused');
  identityDemand(actual.Id === container.container_id && actual.Image === container.image_id && actual.Created === container.created && actual.State?.StartedAt === container.started_at && actual.State.Running === true && actual.Config?.Labels?.['aiui.toolkit.owner'] === container.owner && actual.Config.Labels['aiui.toolkit.nonce'] === container.nonce && actual.HostConfig?.Memory === memoryMax && actual.HostConfig.NanoCpus === 1000000000 && same(actual.Mounts,[]),'actual container/image/incarnation mismatch');
  if (moduleShell) {
    const env = actual.Config.Env;
    identityDemand(Array.isArray(env) && env.every(text) && Object.entries(moduleEnvironment).every(([key,value])=>same(env.filter(entry=>entry.startsWith(`${key}=`)),[`${key}=${value}`])),'ModuleShell actual container environment mismatch');
  }
  identityDemand(transfer.exit_code === 0 && transfer.container_id === container.container_id && transfer.target === c.guest_path && transfer.sha256 === host.sha256 && transfer.bytes === host.bytes && t.guest?.path === c.guest_path && t.guest.sha256?.toUpperCase() === host.sha256 && t.guest.bytes === host.bytes,'transferred guest ELF byte mismatch');
  identityDemand(t.source?.sha256_before === host.sha256 && t.source.sha256_after === host.sha256 && t.source.bytes_sent === host.bytes && t.source.fd_before && same(t.source.fd_before,t.source.fd_after),'host changed during transfer');
  const hostStat = t.source.fd_before, hostStatKeys = ['volume_serial','file_index','nlink','size','creation_time_100ns','last_write_time_100ns','change_time_100ns'];
  identityDemand(Object.keys(hostStat).length === hostStatKeys.length && hostStatKeys.every(key=>typeof hostStat[key] === 'string' && /^\d+$/.test(hostStat[key])) && hostStat.nlink === '1' && BigInt(hostStat.file_index) > 0n && hostStat.size === String(host.bytes),'incomplete actual host transfer FD identity','IDENTITY_NOT_VERIFIED');
  const stage = readProvenanceRef(root,t.stage_receipt);
  identityDemand(path.resolve(stage.source) === host.canonical_path && path.resolve(stage.target) === path.resolve(t.source.path) && stage.sha256 === host.sha256 && stage.bytes === host.bytes,'approved host/staged payload join mismatch');
  identityDemand(ms(container.created) <= ms(t.started_utc) && ms(t.completed_utc) >= ms(t.started_utc) && ms(t.completed_utc) <= ms(witness.started_utc) && ms(witness.started_utc) >= ms(run.started_at) && ms(witness.completed_utc) >= ms(witness.started_utc) && ms(witness.completed_utc) <= ms(run.completed_at),'stale/reused/out-of-order provenance');
  identityDemand(typeof witness.raw_kernel_report_utf8 === 'string' && Buffer.byteLength(witness.raw_kernel_report_utf8) <= 65536 && hash(witness.raw_kernel_report_utf8) === witness.raw_kernel_report_sha256,'missing/changed raw kernel report','IDENTITY_NOT_VERIFIED');
  const invocation = witness.collector_invocation;
  const helperBytes = observeHostFile(root,c.producer.path,{limit:4*1024*1024,capture:true}).content.toString('utf8');
  const program = /KERNEL_FD_PROGRAM = r'''([\s\S]*?)'''/.exec(helperBytes)?.[1];
  identityDemand(text(program) && invocation?.executable === 'C:\\Program Files\\WSL\\wslc.exe' && invocation.exit_code === 0 && invocation.stderr === '' && invocation.stdout_sha256 === witness.raw_kernel_report_sha256 && same(invocation.args,['exec',container.container_id,'bash','-c',program,'toolkit-kernel-fds',String(obs.runtime.pid),c.guest_path,String(obs.runtime.listener_port)]),'raw kernel report not bound to trusted collector invocation');
  identityDemand(/^\d+$/.test(invocation.started_unix_ns ?? '') && /^\d+$/.test(invocation.completed_unix_ns ?? '') && BigInt(invocation.completed_unix_ns) >= BigInt(invocation.started_unix_ns) && Math.abs(Number(BigInt(invocation.started_unix_ns)/1000000n)-ms(witness.started_utc)) <= 1 && Math.abs(Number(BigInt(invocation.completed_unix_ns)/1000000n)-ms(witness.completed_utc)) <= 1,'collector time interval mismatch');
  let k;
  try { k = parseIdentityJson(Buffer.from(witness.raw_kernel_report_utf8)); } catch { identityDemand(false,'truncated kernel report','IDENTITY_NOT_VERIFIED'); }
  identityDemand(k.schema === 'toolkit-wslc-proc-fd-executable-report-v1' && k.guest_path === c.guest_path,'kernel witness schema/path mismatch');
  identityDemand(/^\d+$/.test(k.observed_start_unix_ns ?? '') && /^\d+$/.test(k.observed_end_unix_ns ?? '') && BigInt(k.observed_end_unix_ns) >= BigInt(k.observed_start_unix_ns) && BigInt(k.observed_start_unix_ns) >= BigInt(invocation.started_unix_ns)-2000000000n && BigInt(k.observed_end_unix_ns) <= BigInt(invocation.completed_unix_ns)+2000000000n,'stale/partial guest kernel observation');
  const before = procIdentity(k.before?.proc_stat_raw), after = procIdentity(k.after?.proc_stat_raw), parent = procIdentity(k.parent?.proc_stat_raw);
  identityDemand(same(parent,procIdentity(k.parent.after_proc_stat_raw)) && same(k.parent.argv,k.parent.argv_after),'parent changed during executable verification');
  identityDemand(same(before,after) && k.pid === before.pid && k.pid === obs.runtime.pid && before.birth === obs.runtime.process_start_ticks && before.parent === parent.pid && k.parent.pid === parent.pid,'PID reuse/process birth/parent mismatch');
  identityDemand(text(k.launch_nonce) && /^[a-f0-9]{32}$/.test(k.launch_nonce),'launch nonce not observed','IDENTITY_NOT_VERIFIED');
  const launch = witness.launch_binding;
  identityDemand(launch?.app_pid === before.pid && launch.app_birth === before.birth && launch.parent_pid === parent.pid && launch.parent_birth === parent.birth && launch.launch_nonce === k.launch_nonce && same(launch.parent_argv,k.parent.argv),'observed process not bound to owned launch');
  identityDemand(/^\d+$/.test(launch.started_unix_ns ?? '') && /^\d+$/.test(launch.observed_unix_ns ?? '') && BigInt(launch.observed_unix_ns) >= BigInt(launch.started_unix_ns) && Number(BigInt(launch.started_unix_ns)/1000000n) === ms(obs.runtime.started_at) && Number(BigInt(launch.started_unix_ns)/1000000n) >= ms(run.started_at) && Number(BigInt(launch.observed_unix_ns)/1000000n) <= ms(witness.started_utc),'missing or stale actual launch interval','IDENTITY_NOT_VERIFIED');
  const tag = 'toolkit-wslc-' + hash(witness.session_id).slice(0,24).toLowerCase();
  identityDemand(same(k.parent.argv,['timeout','--signal=TERM','--kill-after=2s',moduleShell?'660s':'300s',c.guest_path,'--remote=127.0.0.1:0',`--remote-title-tag=${tag}`,'--linux-backend=x11']),'foreign launcher command');
  identityDemand(k.before.exe_link === c.guest_path && k.after.exe_link === c.guest_path,'deleted/replaced /proc executable');
  const fileId = kernelFile(k.before.executable_fd_stat);
  for (const stat of [k.after.executable_fd_stat,k.before.guest_path_fd_stat,k.after.guest_path_fd_stat]) identityDemand(kernelFile(stat) === fileId,'post-spawn executable replacement/file hash race');
  identityDemand(Number(k.before.executable_fd_stat.size) === host.bytes && k.executable_fd_sha256?.toUpperCase() === host.sha256 && k.guest_path_fd_sha256?.toUpperCase() === host.sha256,'running ELF differs from approved bytes');
  identityDemand(/^pid:\[[1-9][0-9]*\]$/.test(k.before.pid_namespace ?? '') && /^mnt:\[[1-9][0-9]*\]$/.test(k.before.mount_namespace ?? '') && k.before.pid_namespace === k.after.pid_namespace && k.before.mount_namespace === k.after.mount_namespace && k.before.pid_namespace === obs.runtime.namespace,'process namespace changed or absent');
  const listener = k.listener;
  identityDemand(listener?.host === '127.0.0.1' && Number.isSafeInteger(listener.port) && listener.port > 0 && listener.port <= 65535 && listener.port === obs.runtime.listener_port && /^[1-9][0-9]*$/.test(listener.inode ?? '') && /^\d+$/.test(String(listener.socket_fd)) && listener.socket_fd_link === `socket:[${listener.inode}]`,'listener FD owner mismatch');
  const row = listener.proc_net_tcp_row?.trim().split(/\s+/);
  identityDemand(row?.length >= 10 && row[1] === `0100007F:${listener.port.toString(16).toUpperCase().padStart(4,'0')}` && row[3] === '0A' && row[9] === listener.inode,'actual listener kernel row mismatch');
  const identity = obs.runtime.guest_identity;
  identityDemand(identity?.pid === k.pid && identity.process_start_ticks === before.birth && identity.container_id === container.container_id && identity.image_id === container.image_id && identity.window_id === obs.runtime.window_id && identity.listener_port === listener.port && identity.listener_inode === listener.inode && identity.executable_sha256?.toUpperCase() === host.sha256,'Makepad listener/WindowId/session join missing');
  identityDemand(obs.runtime.platform === 'linux-wslc-owned-container','wrong process namespace/platform');
  return {schema:WSLC_EXECUTABLE_PROVENANCE,artifact_id:c.artifact_id,sha256:host.sha256,container_id:container.container_id,pid:k.pid,process_start_ticks:before.birth,session_id:witness.session_id};
}
