import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  beginRun,
  expectedPostcondition,
  finishRun,
  loadProject,
  planProject,
  resourceAdmission,
  verifyEvidence,
} from '../core/index.mjs';
import {observeHostFile, provenancePath, MODULE_SHELL_BUILD_SCHEMA,
  MODULE_SHELL_SOURCE_SCHEMA, MODULE_SHELL_UPSTREAM_INPUTS} from '../core/executable-provenance.mjs';

// Every byte and receipt in this file is synthetic. The ELF magic prefix is
// followed by text, so this is not a launchable ELF. Nothing is ever executed.
// The accepted-looking event is held in memory for verifyEvidence only; this
// fixture never calls recordProject or produces hardware/UI acceptance.
const profiles = fileURLToPath(new URL('../profiles/', import.meta.url));
const sourceCommit = '71c9ddcbb9c01dd208f99621fdd71024a5d35c65';
const artifactPath = 'artifacts/focus-fixture.elf';
const guestPath = '/workspace/target/debug/focus-fixture';
const buildDir = 'build/sourcebuild34';
const scenarioId = 'synthetic-wslc-provenance';
const moduleEnvironment = [
  'MAKEPAD_HOME=/tmp/toolkit-module-shell-wslc-home',
  'TOOLKIT_MODULE_PROJECT_ID=module-shell-wslc-v1',
  'TOOLKIT_NATIVE_LATE_PROBE=1',
];
const allResources = {
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

const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase();
const jsonBytes = value => Buffer.from(JSON.stringify(value) + '\n', 'utf8');
const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const reverseJsonKeys = value => Array.isArray(value)
  ? value.map(reverseJsonKeys)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().reverse().map(key => [key, reverseJsonKeys(value[key])]))
    : value;

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wslc-provenance-synthetic-'));
  t.after(() => {
    assert.ok(path.basename(root).startsWith('wslc-provenance-synthetic-'));
    fs.rmSync(root, {recursive: true, force: true});
  });
  return root;
}

function makeFixture(t, {
  autoCapture = true,
  reorderJsonKeys = false,
  contractPatch = () => {},
  profilePatch = () => {},
  buildPatch = () => {},
  nativeReceiptBytes = null,
  afterBeginRun = () => {},
  moduleShell = false,
  shellPatch = () => {},
  stagedMainSuffix = '',
} = {}) {
  const root = temporaryRoot(t);
  const hostBytes = Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
    Buffer.from(' SYNTHETIC TEXT FIXTURE; NEVER EXECUTED; NOT A VALID ELF\n', 'ascii'),
  ]);
  const containerId = 'a'.repeat(64);
  const imageId = 'sha256:' + 'b'.repeat(64);
  const owner = 'synthetic-wslc-owner';
  const containerNonce = 'c'.repeat(32);
  const helperPath = 'provenance/synthetic-wslc-host.py';
  const profilePath = 'receipts/trusted-profile.json';
  const buildReceiptPath = buildDir + '/build-result.json';
  const nativeReceiptPath = buildDir + '/nativecompiler.json';
  const sourceManifestPath = buildDir + '/source-manifest.json';
  const witnessPath = 'receipts/running-witness.json';
  const observationPath = 'evidence/' + scenarioId + '-observations.json';
  const reportPath = 'evidence/' + scenarioId + '.json';
  const runPath = 'evidence/' + scenarioId + '-run.json';
  const freezePath = 'source-freeze.json';

  const write = (ref, value) => {
    const file = path.join(root, ref);
    fs.mkdirSync(path.dirname(file), {recursive: true});
    const reorderThisJson = reorderJsonKeys && (
      ref.startsWith('receipts/') || ref.startsWith(buildDir + '/') || ref === freezePath
    );
    fs.writeFileSync(file, Buffer.isBuffer(value) ? value : typeof value === 'string' ? value : jsonBytes(reorderThisJson ? reverseJsonKeys(value) : value));
    return file;
  };
  const h = ref => hash(fs.readFileSync(path.join(root, ref)));
  const read = ref => readJson(path.join(root, ref));
  const ref = pathRef => ({path: pathRef, sha256: h(pathRef)});
  const makeRef = (pathRef, value) => {
    write(pathRef, value);
    return ref(pathRef);
  };

  write(artifactPath, hostBytes);

  const sourceFiles = {
    'fixture/Cargo.toml': '[package]\nname = "focus-fixture"\nversion = "0.1.0"\n',
    'fixture/Cargo.lock': '# synthetic Cargo.lock for sourcebuild34 compatibility\n',
    'fixture/src/main.rs': 'fn main() { focus_trace::record("synthetic"); }\n',
    'fixture/src/focus_trace.rs': 'pub fn record(_: &str) {}\n',
    'operator-plan.json': JSON.stringify({schema: 'synthetic-operator-plan-v1', execute: false}),
  };
  for (const [name, bytes] of Object.entries(sourceFiles)) write(buildDir + '/' + name, bytes);
  const sourceHashes = Object.fromEntries(
    Object.keys(sourceFiles).map(name => [name, h(buildDir + '/' + name)]),
  );
  const harnessPins = [
    sourceHashes['fixture/Cargo.toml'],
    sourceHashes['fixture/Cargo.lock'],
    sourceHashes['fixture/src/main.rs'],
    sourceHashes['fixture/src/focus_trace.rs'],
  ];
  const harness = [
    '# SYNTHETIC build-focus-fixture.sh; never executed',
    ...harnessPins.map(value => '# input-sha256 ' + value),
    'exit 0',
    '',
  ].join('\n');
  write(buildDir + '/build-focus-fixture.sh', harness);

  const sourceEntries = [
    ...Object.keys(sourceFiles).map(name => ({path: buildDir + '/' + name, sha256: sourceHashes[name]})),
    {path: buildDir + '/build-focus-fixture.sh', sha256: h(buildDir + '/build-focus-fixture.sh')},
  ];
  makeRef(sourceManifestPath, {
    schema: 'toolkit-trusted-linux-fixture-build-inputs-v1',
    files: sourceEntries,
  });

  const helperBytes = Buffer.from(
    '# SYNTHETIC provenance helper fixture; never imported or executed\n' +
    "KERNEL_FD_PROGRAM = r'''# SYNTHETIC kernel FD collector program; never executed\n# fixture bytes only'''\n" +
    harnessPins.join('\n') + '\n',
    'utf8',
  );
  write(helperPath, helperBytes);

  const profile = {
    schema: 'toolkit-makepad-remote-wslc-trusted-profile-v1',
    experimental_opt_in: true,
    source_commit: sourceCommit,
    owner,
    runtime_directory: '/tmp/synthetic-wslc-owner',
    helper_sha256: h(helperPath),
    expected_identity: {
      executable: guestPath,
      executable_sha256: h(artifactPath),
      container_id: containerId,
      image_id: imageId,
    },
  };
  profilePatch(profile);
  makeRef(profilePath, profile);

  const actualCompilerArtifact = '/synthetic/sourcebuild34/target/debug/focus-fixture';
  const stdout = [
    JSON.stringify({reason: 'compiler-artifact', executable: actualCompilerArtifact}),
    JSON.stringify({reason: 'build-finished', success: true}),
    h(artifactPath) + '  ' + actualCompilerArtifact,
  ].join('\n');
  const scriptAbs = path.resolve(root, buildDir + '/build-focus-fixture.sh').replaceAll('\\', '/');
  const mountedScript = process.platform === 'win32'
    ? '/mnt/' + scriptAbs[0].toLowerCase() + scriptAbs.slice(2)
    : scriptAbs;
  const nativeReceipt = {
    exit_code: 0,
    timed_out: false,
    output_drained: true,
    executable: 'C:/Windows/System32/wsl.exe',
    args: ['-d', 'Ubuntu', '--exec', '/bin/bash', mountedScript],
    stdout,
  };
  write(nativeReceiptPath, nativeReceiptBytes ?? nativeReceipt);

  const buildReceipt = {
    schema: 'toolkit-linux-focus-fixture-build-result-v1',
    exit_code: 0,
    timed_out: false,
    output_drained: true,
    artifact: {
      sha256: h(artifactPath),
      bytes: hostBytes.length,
      actual_compiler_artifact: actualCompilerArtifact,
    },
    source: {
      SDK_pin: sourceCommit,
      portable_main_sha256: sourceHashes['fixture/src/main.rs'],
      portable_trace_sha256: sourceHashes['fixture/src/focus_trace.rs'],
      fixture_lock_unchanged: sourceHashes['fixture/Cargo.lock'],
    },
    receipt: 'nativecompiler.json',
  };
  buildPatch(buildReceipt);
  makeRef(buildReceiptPath, buildReceipt);

  if (moduleShell) {
    makeModuleShellBuild({root,write,h,ref,profile,profilePath,buildReceiptPath,
      nativeReceiptPath,sourceManifestPath,artifactPath,hostBytes,shellPatch,stagedMainSuffix});
    sourceEntries.splice(0,sourceEntries.length,...read(sourceManifestPath).files);
  }

  const contract = {
    schema: 'toolkit-wslc-host-guest-executable-provenance-v1',
    artifact_id: 'synthetic-focus-fixture',
    host_path: artifactPath,
    guest_path: guestPath,
    sha256: h(artifactPath),
    bytes: hostBytes.length,
    profile: ref(profilePath),
    build_receipt: ref(buildReceiptPath),
    native_build_receipt: ref(nativeReceiptPath),
    source_manifest: ref(sourceManifestPath),
    producer: ref(helperPath),
  };
  contractPatch(contract, {root, artifactPath});

  const rawPolicy = readJson(path.join(
    profiles,
    'makepad-semantic',
    'verification/verification-policy.json',
  ));
  const composition = structuredClone(
    rawPolicy.scenario_registry.find(s => s.level === 'L4b'),
  );
  Object.assign(composition, {
    id: scenarioId,
    owner: 'synthetic-provenance-tests',
    file: 'verification/scenarios/wslc-executable-provenance.aiui.json',
    level: 'L4b',
    status: 'RISK_TRIGGERED',
    stability: 'stable',
    cost: 'expensive',
    risk_tags: [],
    features_proven: [],
    lower_level_coverage: ['contract-unit', 'launcher-contract'],
    run_when: [],
    periodic: true,
    default_periodic: true,
    resources: [],
    require_native_captures: false,
    executable_provenance: contract,
  });
  rawPolicy.scenario_registry = [composition];
  const recipe = {
    version: 1,
    name: 'synthetic-wslc-executable-provenance',
    application: {command: guestPath},
    setup: [{op: 'session.open', save_session_as: 'app'}],
    steps: [
      {op: 'get_runtime_health', session: 'app'},
      {op: 'get_runtime_stderr', session: 'app'},
    ],
    teardown: [{op: 'session.close', session: 'app'}],
    options: {stop_on_error: true, evidence_on_failure: true},
  };
  write(composition.file, recipe);

  const binding = readJson(path.join(
    profiles,
    'makepad-linux-wslc',
    'verification/toolkit-core.json',
  ));
  binding.project_id = 'synthetic.wslc.executable-provenance';
  write('verification/toolkit-core.json', binding);
  write('verification/verification-policy.json', rawPolicy);

  const frozen = [
    contract.profile,
    contract.build_receipt,
    contract.native_build_receipt,
    contract.source_manifest,
    contract.producer,
    ...sourceEntries,
  ];
  write(freezePath, frozen);
  const policy = loadProject(root);
  const plan = planProject(policy, {
    milestone_id: 'SYNTHETIC-WSLC-PROVENANCE',
    changed_modules: ['pure'],
    artifact: {path: artifactPath, sha256: h(artifactPath)},
    available_resources: allResources,
  });
  write('quality.json', {
    artifact: {sha256: h(artifactPath)},
    source_freeze_sha256: h(freezePath),
    completed_at: new Date().toISOString(),
    gates: ['L0', 'L1', 'L2']
      .flatMap(level => plan.required[level])
      .map(gate => ({id: gate.id, exit_code: 0})),
  });

  const f = {
    root,
    policy,
    plan,
    contract,
    hostBytes,
    containerId,
    imageId,
    owner,
    containerNonce,
    witnessPath,
    observationPath,
    reportPath,
    runPath,
    freezePath,
    artifactPath,
    guestPath,
    buildReceiptPath,
    nativeReceiptPath,
    sourceManifestPath,
    profilePath,
    write,
    h,
    read,
    capture,
    verify: () => verifyEvidence(root, policy, f.event, f.plan),
    editWitness,
    editObservation,
    rewriteRef,
  };

  function rewriteRef(refValue, value, alternatePath = refValue.path) {
    write(alternatePath, value);
    return {path: alternatePath, sha256: h(alternatePath)};
  }

  function sealObservation() {
    const observation = read(observationPath);
    observation.runtime.executable_provenance.sha256 = h(witnessPath);
    for (const rawRef of observation.raw_provenance ?? []) rawRef.sha256 = h(rawRef.path);
    write(observationPath, observation);
    const run = read(runPath);
    run.observation_sha256 = h(observationPath);
    write(runPath, run);
  }

  function editWitness(mutator) {
    const witness = read(witnessPath);
    const api = {
      readRef: refValue => read(refValue.path),
      writeRef: (refValue, value, alternatePath = refValue.path) =>
        rewriteRef(refValue, value, alternatePath),
    };
    mutator(witness, api);
    write(witnessPath, witness);
    sealObservation();
  }

  function editObservation(mutator) {
    const observation = read(observationPath);
    mutator(observation);
    write(observationPath, observation);
    const run = read(runPath);
    run.observation_sha256 = h(observationPath);
    write(runPath, run);
  }

  function capture() {
    assert.equal(f.run, undefined, 'synthetic capture is single use');
    const plan=f.plan;
    const run = beginRun(root, policy, plan, scenarioId, freezePath);
    const startMs = Date.parse(run.started_at);
    const launchBoundaryNs = String(BigInt(startMs) * 1_000_000n);
    afterBeginRun({root, run, artifactPath, hostBytes});
    const hostNowNs = BigInt(Date.now()) * 1_000_000n;
    const stamp = new Date(Number(hostNowNs / 1_000_000n)).toISOString();
    const container = {
      container_id: containerId,
      image_id: imageId,
      owner,
      nonce: containerNonce,
      created: new Date(startMs - 10_000).toISOString(),
      started_at: new Date(startMs - 9_000).toISOString(),
    };
    const sessionId = 'synthetic-owner-session-7';
    const sessionTitleTag = crypto.createHash('sha256').update(sessionId, 'utf8').digest('hex').slice(0, 24);
    const generation = 7;
    const appPid = 4242;
    const appBirth = '700000';
    const parentPid = 4000;
    const parentBirth = '600000';
    const launchNonce = 'd'.repeat(32);
    const parentArgv = [
      'timeout',
      '--signal=TERM',
      '--kill-after=2s',
      moduleShell ? '660s' : '300s',
      guestPath,
      '--remote=127.0.0.1:0',
      '--remote-title-tag=toolkit-wslc-' + sessionTitleTag,
      '--linux-backend=x11',
    ];

    const context = {
      container_id: container.container_id,
      image: container.image_id,
      exclusive_owner: container.owner,
      exclusive_nonce: container.nonce,
      container_created: container.created,
      container_started_at: container.started_at,
      owns_container: true,
      owns_vm: false,
      resumable: false,
      source_revision: sourceCommit,
      ...(moduleShell ? {
        wslc_profile: 'wslc_multi_module',
        module_shell_profile_kind: 'ModuleShell',
        module_shell_source_manifest_sha256: h(sourceManifestPath),
        memory_max: 2147483648,
        cpus: 1,
        module_instances: 2,
        module_shell_makepad_home: '/tmp/toolkit-module-shell-wslc-home',
        module_shell_project_id: 'module-shell-wslc-v1',
        module_shell_native_late_probe: '1',
      } : {}),
    };
    const contextRef = makeRef('receipts/owner-context.json', context);
    const createArgs = [
      'run', '--detach', '--rm', '--name', 'aiui-workspace-20261008',
      '--memory', moduleShell ? '2G' : '1G', '--cpus', '1', '--gpus', 'all',
      ...(moduleShell ? moduleEnvironment.flatMap(value => ['--env', value]) : []),
      '--label', 'aiui.toolkit.owner=' + owner,
      '--label', 'aiui.toolkit.nonce=' + container.nonce,
      container.image_id, 'sleep', '1800',
    ];
    const creatorRef = makeRef('receipts/container-create.json', {
      exit_code: 0,
      timed_out: false,
      output_drained: true,
      stdout: container.container_id,
      args: createArgs,
    });
    const inspectValue = [{
      Id: container.container_id,
      Image: container.image_id,
      Created: container.created,
      State: {StartedAt: container.started_at, Running: true},
      Config: {
        Labels: {'aiui.toolkit.owner': owner, 'aiui.toolkit.nonce': container.nonce},
        ...(moduleShell ? {Env: ['PATH=/usr/local/bin:/usr/bin:/bin', ...moduleEnvironment]} : {}),
      },
      HostConfig: {Memory: moduleShell ? 2147483648 : 1073741824, NanoCpus: 1000000000},
      Mounts: [],
    }];
    const inspectRef = makeRef('receipts/container-inspect.json', {
      exit_code: 0,
      timed_out: false,
      output_drained: true,
      stdout: JSON.stringify(inspectValue),
    });
    const stagePath = path.join(root, 'transfer-staging/focus-fixture.elf');
    const stageRef = makeRef('receipts/host-stage.json', {
      source: path.join(root, artifactPath),
      target: stagePath,
      sha256: h(artifactPath),
      bytes: hostBytes.length,
    });
    const ownerConfigRef = makeRef('receipts/owner-config.json', {
      owner,
      source_commit: sourceCommit,
      session_id: sessionId,
      generation,
      expected_identity: readJson(path.join(root, profilePath)).expected_identity,
      runtime_directory: '/tmp/synthetic-wslc-owner',
      ...(moduleShell ? {
        profile_kind: 'ModuleShell',
        module_shell: {source_manifest_sha256: h(sourceManifestPath)},
      } : {}),
    });
    const transferProvenance = {
      schema: 'toolkit-wslc-artifact-transfer-provenance-v1',
      operation_id: crypto.randomUUID(),
      container,
      context: contextRef,
      creator_receipt: creatorRef,
      container_inspect_receipt: inspectRef,
      stage_receipt: stageRef,
      source: {
        path: stagePath,
        sha256_before: h(artifactPath),
        sha256_after: h(artifactPath),
        bytes_sent: hostBytes.length,
        fd_before: {
          volume_serial: '8',
          file_index: '900001',
          nlink: '1',
          size: String(hostBytes.length),
          creation_time_100ns: '133444736000000000',
          last_write_time_100ns: '133444736000000000',
          change_time_100ns: '133444736000000000',
        },
        fd_after: {
          volume_serial: '8',
          file_index: '900001',
          nlink: '1',
          size: String(hostBytes.length),
          creation_time_100ns: '133444736000000000',
          last_write_time_100ns: '133444736000000000',
          change_time_100ns: '133444736000000000',
        },
      },
      guest: {path: guestPath, sha256: h(artifactPath), bytes: hostBytes.length},
      started_utc: stamp,
      completed_utc: stamp,
    };
    const transferRef = makeRef('receipts/artifact-transfer.json', {
      exit_code: 0,
      container_id: container.container_id,
      target: guestPath,
      sha256: h(artifactPath),
      bytes: hostBytes.length,
      provenance: transferProvenance,
    });

    const fileIdentity = {
      dev: '8',
      inode: '900001',
      size: String(hostBytes.length),
      nlink: '1',
      ctime_ns: '1700000000000',
    };
    const pidNamespace = 'pid:[101]';
    const mountNamespace = 'mnt:[201]';
    const listenerPort = 25679;
    const listenerInode = '123456';
    const portHex = listenerPort.toString(16).toUpperCase().padStart(4, '0');
    const kernel = {
      schema: 'toolkit-wslc-proc-fd-executable-report-v1',
      guest_path: guestPath,
      observed_start_unix_ns: String(hostNowNs),
      observed_end_unix_ns: String(hostNowNs),
      pid: appPid,
      before: {
        proc_stat_raw: procStat(appPid, 'focus-fixture', 'S', parentPid, appBirth),
        exe_link: guestPath,
        executable_fd_stat: structuredClone(fileIdentity),
        guest_path_fd_stat: structuredClone(fileIdentity),
        pid_namespace: pidNamespace,
        mount_namespace: mountNamespace,
      },
      after: {
        proc_stat_raw: procStat(appPid, 'focus-fixture', 'S', parentPid, appBirth),
        exe_link: guestPath,
        executable_fd_stat: structuredClone(fileIdentity),
        guest_path_fd_stat: structuredClone(fileIdentity),
        pid_namespace: pidNamespace,
        mount_namespace: mountNamespace,
      },
      parent: {
        pid: parentPid,
        proc_stat_raw: procStat(parentPid, 'timeout', 'S', 1, parentBirth),
        after_proc_stat_raw: procStat(parentPid, 'timeout', 'S', 1, parentBirth),
        argv: parentArgv,
        argv_after: [...parentArgv],
      },
      launch_nonce: launchNonce,
      executable_fd_sha256: h(artifactPath),
      guest_path_fd_sha256: h(artifactPath),
      listener: {
        host: '127.0.0.1',
        port: listenerPort,
        inode: listenerInode,
        socket_fd: 9,
        socket_fd_link: 'socket:[' + listenerInode + ']',
        proc_net_tcp_row: [
          '0:',
          '0100007F:' + portHex,
          '00000000:0000',
          '0A',
          '00000000:00000000',
          '00:00000000',
          '00000000',
          '1000',
          '0',
          listenerInode,
          '1',
        ].join(' '),
      },
    };
    const rawKernel = JSON.stringify(reorderJsonKeys ? reverseJsonKeys(kernel) : kernel);
    const rawKernelSha256 = hash(Buffer.from(rawKernel, 'utf8'));
    const witness = {
      schema: 'toolkit-wslc-running-executable-witness-v1',
      source_commit: sourceCommit,
      owner,
      session_id: sessionId,
      generation,
      helper: contract.producer,
      container,
      owner_config: ownerConfigRef,
      context: contextRef,
      creator_receipt: creatorRef,
      transfer_receipt: transferRef,
      launch_binding: {
        app_pid: appPid,
        app_birth: appBirth,
        parent_pid: parentPid,
        parent_birth: parentBirth,
        launch_nonce: launchNonce,
        parent_argv: parentArgv,
        started_unix_ns: launchBoundaryNs,
        observed_unix_ns: launchBoundaryNs,
      },
      collector_invocation: {
        executable: 'C:\\Program Files\\WSL\\wslc.exe',
        args: [
          'exec', containerId, 'bash', '-c',
          "# SYNTHETIC kernel FD collector program; never executed\n# fixture bytes only",
          'toolkit-kernel-fds', String(appPid), guestPath, String(listenerPort),
        ],
        exit_code: 0,
        stderr: '',
        stdout_sha256: rawKernelSha256,
        started_unix_ns: String(hostNowNs),
        completed_unix_ns: String(hostNowNs),
      },
      raw_kernel_report_utf8: rawKernel,
      raw_kernel_report_sha256: rawKernelSha256,
      started_utc: stamp,
      completed_utc: stamp,
    };
    write(witnessPath, witness);

    const recipeOnDisk = readJson(path.join(root, policy.scenario_registry[0].file));
    const steps = [
      ...(recipeOnDisk.setup ?? []),
      ...recipeOnDisk.steps,
      ...(recipeOnDisk.teardown ?? []),
    ];
    const report = {
      test: recipeOnDisk.name,
      status: 'PASSED',
      summary: {passed: steps.length, total: steps.length, failed: 0, skipped: 0},
      steps: steps.map((step, index) => ({
        index,
        step: index < steps.length - recipeOnDisk.teardown.length
          ? 'step-' + index
          : 'teardown-' + (index - (steps.length - recipeOnDisk.teardown.length)),
        operation: step.op,
        status: 'PASS',
        response: {
          result: step.op === 'get_runtime_health'
            ? {healthy: true, process_alive: true}
            : step.op === 'get_runtime_stderr'
              ? []
              : true,
        },
      })),
    };
    const observation = {
      schema_version: 2,
      evidence_origin: 'real',
      producer_kind: 'native-runtime-observer',
      project_id: policy.project_id,
      scenario_id: scenarioId,
      run_id: run.run_id,
      plan_digest: plan.plan_digest,
      runtime: {
        pid: appPid,
        namespace: pidNamespace,
        platform: 'linux-wslc-owned-container',
        window_id: 'synthetic-window-identity',
        artifact_sha256: h(artifactPath),
        started_at: run.started_at,
        owner,
        session_id: sessionId,
        session_generation: generation,
        process_start_ticks: appBirth,
        listener_port: listenerPort,
        executable_provenance: ref(witnessPath),
        guest_identity: {
          pid: appPid,
          process_start_ticks: appBirth,
          container_id: container.container_id,
          image_id: container.image_id,
          window_id: 'synthetic-window-identity',
          listener_port: listenerPort,
          listener_inode: listenerInode,
          executable_sha256: h(artifactPath),
        },
      },
      health: {
        healthy: true,
        process_alive: true,
        observation_source: 'synthetic-health-readback',
      },
      available_resources: plan.planning_input.available_resources,
      steps: [],
    };
    for (let index = 0; index < steps.length; index++) {
      const correlationId = run.run_id + ':' + index;
      const evidencePath = 'evidence/' + scenarioId + '-' + index + '-state.json';
      const expected = expectedPostcondition(policy.scenario_registry[0], steps[index], index);
      write(evidencePath, {
        evidence_origin: 'real',
        run_id: run.run_id,
        correlation_id: correlationId,
        operation: steps[index].op,
        observation_source: 'synthetic-state-readback',
        actual_state: expected,
        expected_state: expected,
      });
      observation.steps.push({
        index,
        operation: steps[index].op,
        correlation_id: correlationId,
        action_dispatched: true,
        postcondition_verified: true,
        observation_source: 'synthetic-state-readback',
        dispatched_at: run.started_at,
        observed_at: run.started_at,
        evidence_path: evidencePath,
        evidence_sha256: h(evidencePath),
      });
    }
    const cleanupPath = 'evidence/' + scenarioId + '-cleanup.json';
    write(cleanupPath, {
      evidence_origin: 'real',
      run_id: run.run_id,
      orphan_processes: 0,
      stuck_pointer_buttons: 0,
      stuck_modifiers: 0,
      active_input_leases: 0,
      stale_windows: 0,
      leaked_resources: 0,
    });
    observation.cleanup = {
      pointer_buttons_released: true,
      modifiers_released: true,
      input_leases_released: true,
      processes_exited: true,
      windows_closed: true,
      worker_resources_released: true,
      evidence_path: cleanupPath,
      evidence_sha256: h(cleanupPath),
    };

    write(reportPath, report);
    observation.raw_provenance = [
      {path: reportPath, sha256: h(reportPath)},
      {path: observation.runtime.executable_provenance.path, sha256: h(observation.runtime.executable_provenance.path)},
    ];
    write(observationPath, observation);
    // Only these synthetic files use a controlled filesystem clock. A host
    // timestamp rounded below the run boundary must not mask the target check.
    const fixtureTime = new Date(Math.max(Date.now(), Date.parse(run.started_at)));
    for (const file of [reportPath, observationPath]) fs.utimesSync(path.join(root,file),fixtureTime,fixtureTime);
    const finished = finishRun(root, run, reportPath, observationPath);
    write(runPath, finished);
    f.run = finished;
    f.event = {
      project_id: policy.project_id,
      evidence_version: 2,
      milestone: plan.milestone,
      status: 'ACCEPTED',
      kind: 'functional',
      expanded_gui: plan.l4b_required,
      artifact_hash: h(artifactPath),
      artifact_path: artifactPath,
      quality_report: 'quality.json',
      source_freeze: freezePath,
      date: '2026-10-23',
      scenario_results: [{
        id: scenarioId,
        status: 'PASS',
        artifact_hash: h(artifactPath),
        report: reportPath,
        run_manifest: runPath,
      }],
    };
    return f;
  }

  if (autoCapture) capture();
  return f;
}

// Synthetic producer bytes only. This exercises the real beginRun/Core path
// with the newly supported shape, without Cargo, WSL or executable code.
function makeModuleShellBuild({root,write,h,ref,profile,profilePath,buildReceiptPath,
  nativeReceiptPath,sourceManifestPath,artifactPath,hostBytes,shellPatch,stagedMainSuffix}) {
  const files = [];
  const put = (name,bytes) => {
    const p = `${buildDir}/shell/${name}`;write(p,bytes);
    const pin = {path:p,sha256:h(p),bytes:Buffer.byteLength(bytes)};files.push(pin);return pin;
  };
  const upstreamRoot = '/synthetic/pinned-makepad71';
  const upstreamFiles = MODULE_SHELL_UPSTREAM_INPUTS.map(relative_path=>({relative_path,
    ...put(`upstream/${relative_path}`,`// synthetic pinned input ${relative_path}; never executed\n`)}));
  const oldMainPath = '#[path = "../../../reports/evidence/makepad-dev-capability-audit-20261015/upstream/apps/wm/src/module_host.rs"]';
  const newMainPath = `#[path = "${upstreamRoot}/apps/wm/src/module_host.rs"]`;
  const originalMainText = `${oldMainPath}\nmod module_host;\nfn main() {}\n`;
  const originalMain = put('original/src/main.rs',originalMainText);
  const main = put('compiled/src/main.rs',originalMainText.replace(oldMainPath,newMainPath)+stagedMainSuffix);
  const depDirs = ['widgets','libs/app_module','libs/wm_theme','libs/core_util','libs/strict_json'];
  const replacements = depDirs.map(dir=>({
    from:`path = "../../reports/evidence/makepad-dev-capability-audit-20261015/upstream/${dir}"`,
    to:`path = "${upstreamRoot}/${dir}"`,count:1}));
  const originalCargoText = '[package]\nname = "toolkit-app-module-shell"\nversion = "0.1.0"\n[dependencies]\n'
    + replacements.map((r,i)=>`dependency${i} = { ${r.from} }`).join('\n')+'\n';
  const originalCargo = put('original/Cargo.toml',originalCargoText);
  let stagedCargo = originalCargoText;
  for(const r of replacements) stagedCargo = stagedCargo.replace(r.from,r.to);
  const cargoManifest = put('compiled/Cargo.toml',stagedCargo);
  const cargoLock = put('compiled/Cargo.lock','# synthetic shell lock; never used by Cargo\n');
  const rustSources = [{relative_path:'src/main.rs',...main}, ...['lib','fixtures','tile'].map(name=>({
    relative_path:`src/${name}.rs`,...put(`compiled/src/${name}.rs`,`// synthetic ${name}\n`)}))];
  const operatorPlan = put('operator-plan.json',JSON.stringify({schema:'synthetic-shell-operator-plan',execute:false}));
  const harness = put('build-module-shell.sh','# synthetic shell compiler harness; never executed\n'
    +files.map(e=>`# input-sha256 ${e.sha256}`).join('\n')+'\n');
  const sources = {schema:MODULE_SHELL_SOURCE_SCHEMA,profile_kind:'ModuleShell',source_commit:sourceCommit,
    files,upstream:{linux_root:upstreamRoot,files:upstreamFiles},
    compiled:{linux_root:'/synthetic/module-shell',target_dir:'/synthetic/module-shell-target',
      cargo_manifest:cargoManifest,cargo_lock:cargoLock,rust_sources:rustSources},
    transformations:[
      {kind:'module-host-path',input:originalMain,output:main,replacements:[{from:oldMainPath,to:newMainPath,count:1}]},
      {kind:'cargo-paths',input:originalCargo,output:cargoManifest,replacements}],
    harness,operator_plan:operatorPlan};
  const target = 'x86_64-unknown-linux-gnu';
  const executable = `/synthetic/module-shell-target/${target}/debug/toolkit-app-module-shell`;
  const args = ['build','--manifest-path','/synthetic/module-shell/Cargo.toml','--bin','toolkit-app-module-shell',
    '--locked','--offline','-j','1','--target',target,'--target-dir','/synthetic/module-shell-target',
    '--message-format=json-render-diagnostics'];
  const build = {schema:MODULE_SHELL_BUILD_SCHEMA,profile_kind:'ModuleShell',exit_code:0,timed_out:false,
    output_drained:true,receipt:'nativecompiler.json',source:{SDK_pin:sourceCommit},
    before:structuredClone(files),after:structuredClone(files),
    toolchain:{target,rustc_vv:`rustc 1.90.0 (synthetic)\ncommit-hash: ${'a'.repeat(40)}\nhost: ${target}\n`,
      cargo_version:'cargo 1.90.0 (synthetic)'},cargo:{args},
    artifact:{sha256:h(artifactPath),bytes:hostBytes.length,actual_compiler_artifact:executable}};
  const abs = path.resolve(root,harness.path).replaceAll('\\','/');
  const mounted = process.platform === 'win32' ? `/mnt/${abs[0].toLowerCase()}${abs.slice(2)}` : abs;
  const marker = (name,value)=>`TOOLKIT_MODULE_SHELL_${name} ${JSON.stringify(value)}`;
  const native = {exit_code:0,timed_out:false,output_drained:true,executable:'C:/Windows/System32/wsl.exe',
    args:['-d','Ubuntu','--exec','/bin/bash',mounted],stdout:[
      marker('BEFORE',build.before),marker('TOOLCHAIN',build.toolchain),marker('COMMAND',args),
      JSON.stringify({reason:'compiler-artifact',executable,target:{name:'toolkit-app-module-shell',kind:['bin'],src_path:'/synthetic/module-shell/src/main.rs'}}),
      JSON.stringify({reason:'build-finished',success:true}),marker('AFTER',build.after),
      marker('ARTIFACT',build.artifact),`${h(artifactPath)}  ${executable}`].join('\n')};
  profile.profile_kind = 'ModuleShell';profile.module_shell = {};
  shellPatch({sources,build,native,profile,write,h,ref});
  write(sourceManifestPath,sources);
  const manifestHash = h(sourceManifestPath);
  profile.module_shell.source_manifest_sha256 = manifestHash;
  build.source.source_manifest_sha256 = manifestHash;
  write(profilePath,profile);write(buildReceiptPath,build);write(nativeReceiptPath,native);
}

function procStat(pid, comm, state, parentPid, birth) {
  const fields = Array(20).fill('0');
  fields[0] = state;
  fields[1] = String(parentPid);
  fields[19] = String(birth);
  return String(pid) + ' (' + comm + ') ' + fields.join(' ');
}

// Reseal only synthetic receipt edges so each negative reaches its intended
// real Core check, rather than failing on an unrelated stale reference hash.
function editContainerReceipts(witness, api, mutate) {
  const context = api.readRef(witness.context);
  const config = api.readRef(witness.owner_config);
  const creator = api.readRef(witness.creator_receipt);
  const transfer = api.readRef(witness.transfer_receipt);
  const inspection = api.readRef(transfer.provenance.container_inspect_receipt);
  const inspected = JSON.parse(inspection.stdout);
  mutate({context, config, creator, actual: inspected[0]});
  witness.context = api.writeRef(witness.context, context);
  witness.owner_config = api.writeRef(witness.owner_config, config);
  witness.creator_receipt = api.writeRef(witness.creator_receipt, creator);
  transfer.provenance.context = witness.context;
  transfer.provenance.creator_receipt = witness.creator_receipt;
  inspection.stdout = JSON.stringify(inspected);
  transfer.provenance.container_inspect_receipt = api.writeRef(
    transfer.provenance.container_inspect_receipt, inspection,
  );
  witness.transfer_receipt = api.writeRef(witness.transfer_receipt, transfer);
}

test('complete synthetic source/build/transfer/kernel contract passes Core v2 verifyEvidence', t => {
  const f = makeFixture(t);
  assert.equal(f.plan.status, 'PLANNED');
  assert.deepEqual(f.plan.selected_scenario_ids, [scenarioId]);
  assert.equal(f.verify().verified_proof, true);
  assert.equal(f.read(f.runPath).status, 'CAPTURED');
});

test('complete synthetic contract accepts reordered JSON object keys', t => {
  const f = makeFixture(t, {reorderJsonKeys: true});
  assert.equal(f.verify().verified_proof, true);
});

test('synthetic ModuleShell 2 GiB/CPU1 profile reaches the full Core v2 transfer/kernel verifier', t => {
  const f = makeFixture(t,{moduleShell:true});
  assert.equal(f.verify().verified_proof,true);
  assert.equal(f.read(f.profilePath).profile_kind,'ModuleShell');
  assert.equal(f.read(f.buildReceiptPath).schema,MODULE_SHELL_BUILD_SCHEMA);
  const witness = f.read(f.witnessPath);
  const context = f.read(witness.context.path);
  assert.equal(context.module_shell_source_manifest_sha256,f.contract.source_manifest.sha256);
  assert.equal(context.memory_max,2147483648);
  assert.equal(context.module_instances,2);
  assert.deepEqual(f.read(witness.creator_receipt.path).args.slice(5,17),[
    '--memory','2G','--cpus','1','--gpus','all',
    '--env','MAKEPAD_HOME=/tmp/toolkit-module-shell-wslc-home',
    '--env','TOOLKIT_MODULE_PROJECT_ID=module-shell-wslc-v1',
    '--env','TOOLKIT_NATIVE_LATE_PROBE=1',
  ]);
});

test('synthetic ModuleShell accepts reordered JSON keys and image-default environment entries', t => {
  const f = makeFixture(t,{moduleShell:true,reorderJsonKeys:true});
  f.editWitness((w,api)=>editContainerReceipts(w,api,({actual})=>{actual.Config.Env.reverse();}));
  assert.equal(f.verify().verified_proof,true);
});

test('explicit FocusFixture keeps the original synthetic 1 GiB contract', t => {
  const f = makeFixture(t,{profilePatch:profile=>{profile.profile_kind='FocusFixture';}});
  assert.equal(f.verify().verified_proof,true);
});

test('ModuleShell still requires the trusted experimental opt-in before resource verification', t => {
  const f = makeFixture(t,{moduleShell:true,autoCapture:false,
    profilePatch:profile=>{delete profile.experimental_opt_in;}});
  assert.throws(()=>f.capture(),/untrusted WSLC profile/);
});

for (const profileKind of ['ModuleShell','FocusFixture',undefined]) {
  test(`${profileKind??'no-kind'} cannot plan from an unbound USER_WAIVED RAM projection`, t => {
    const f = makeFixture(t,{autoCapture:false,moduleShell:profileKind==='ModuleShell',
      profilePatch:profile=>{if(profileKind==='FocusFixture')profile.profile_kind=profileKind;}});
    const available = {...allResources,host_runtime_budget_mib:2560,ram_admission:{
      status:'USER_WAIVED',available_memory_query_performed:false,resource_admitted:false,
      container_memory_bytes:2147483648,container_cpus:1,nested_increment_kib:0,
    }};
    delete available.available_ram_mib;
    const plan = planProject(f.policy,{...f.plan.planning_input,available_resources:available});
    assert.equal(plan.status,'BLOCKED_ENVIRONMENT');
    assert.deepEqual(plan.resource_admission,{status:'BLOCKED_ENVIRONMENT',blockers:['insufficient_available_ram']});
    assert.throws(()=>beginRun(f.root,f.policy,plan,scenarioId,f.freezePath),/plan is not executable\/acceptable/);
    // Even complete-looking receipt fields are not a native immutable ref or
    // a source/owner-bound Core waiver. No reported free value is fabricated.
    available.ram_admission={...available.ram_admission,
      schema:'toolkit-makepad-dev-app-module-shell-host-admission-v1',utc:new Date().toISOString(),
      owner:f.owner,source_manifest_sha256:f.contract.source_manifest.sha256,
      host_ram_mode:'USER_WAIVED',minimum_free_bytes:2684354560,minimum_free_kib:2621440,
      active_compiler_observation_performed:true,active_rust_compilers:[],scope:'one_outer_runtime_admission',
    };
    assert.deepEqual(resourceAdmission(plan.resource_requirements,available),
      {status:'BLOCKED_ENVIRONMENT',blockers:['insufficient_available_ram']});
    assert.equal(Object.hasOwn(available,'available_ram_mib'),false);
  });
}

for (const missing of [false,true]) {
  test(`ModuleShell 2 GiB resources cannot replace a ${missing?'missing':'foreign'} trusted source join`, t => {
    const f = makeFixture(t,{moduleShell:true,autoCapture:false,contractPatch:(c,{root})=>{
      const file = path.join(root,c.profile.path), profile = readJson(file);
      if (missing) delete profile.module_shell.source_manifest_sha256;
      else profile.module_shell.source_manifest_sha256 = 'F'.repeat(64);
      fs.writeFileSync(file,jsonBytes(profile));
      c.profile.sha256 = hash(fs.readFileSync(file));
    }});
    assert.throws(()=>f.capture(),/ModuleShell source set not approved by trusted profile/);
  });
}

const shellResourceNegatives = [
  ['missing multi-module context opt-in',({context})=>{delete context.wslc_profile;},/ModuleShell trusted resource profile\/source join mismatch/],
  ['foreign context profile',({context})=>{context.wslc_profile='wslc_fixture';},/ModuleShell trusted resource profile\/source join mismatch/],
  ['missing context profile kind',({context})=>{delete context.module_shell_profile_kind;},/ModuleShell trusted resource profile\/source join mismatch/],
  ['missing context source join',({context})=>{delete context.module_shell_source_manifest_sha256;},/ModuleShell trusted resource profile\/source join mismatch/],
  ['foreign context source join',({context})=>{context.module_shell_source_manifest_sha256='F'.repeat(64);},/ModuleShell trusted resource profile\/source join mismatch/],
  ['one GiB context',({context})=>{context.memory_max=1073741824;},/ModuleShell exact context resource limits mismatch/],
  ['missing context memory',({context})=>{delete context.memory_max;},/ModuleShell exact context resource limits mismatch/],
  ['string context memory',({context})=>{context.memory_max='2147483648';},/ModuleShell exact context resource limits mismatch/],
  ['two context CPUs',({context})=>{context.cpus=2;},/ModuleShell exact context resource limits mismatch/],
  ['one module instance',({context})=>{context.module_instances=1;},/ModuleShell exact context resource limits mismatch/],
  ['three module instances',({context})=>{context.module_instances=3;},/ModuleShell exact context resource limits mismatch/],
  ['string module count',({context})=>{context.module_instances='2';},/ModuleShell exact context resource limits mismatch/],
  ['missing owner profile kind',({config})=>{delete config.profile_kind;},/ModuleShell owner configuration\/source join mismatch/],
  ['foreign owner profile kind',({config})=>{config.profile_kind='FocusFixture';},/ModuleShell owner configuration\/source join mismatch/],
  ['missing owner source join',({config})=>{delete config.module_shell;},/ModuleShell owner configuration\/source join mismatch/],
  ['foreign owner source join',({config})=>{config.module_shell.source_manifest_sha256='F'.repeat(64);},/ModuleShell owner configuration\/source join mismatch/],
  ['one GiB creator',({creator})=>{creator.args[6]='1G';},/exact owned creator receipt mismatch/],
  ['two creator CPUs',({creator})=>{creator.args[8]='2';},/exact owned creator receipt mismatch/],
  ['missing creator environment',({creator})=>{creator.args.splice(11,6);},/exact owned creator receipt mismatch/],
  ['reordered creator environment',({creator})=>{[creator.args[12],creator.args[14]]=[creator.args[14],creator.args[12]];},/exact owned creator receipt mismatch/],
  ['creator environment after labels',({creator})=>{const env=creator.args.splice(11,6);creator.args.splice(15,0,...env);},/exact owned creator receipt mismatch/],
  ['duplicate creator environment',({creator})=>{creator.args.splice(11,0,'--env',moduleEnvironment[0]);},/exact owned creator receipt mismatch/],
  ['one GiB actual memory',({actual})=>{actual.HostConfig.Memory=1073741824;},/actual container\/image\/incarnation mismatch/],
  ['three GiB actual memory',({actual})=>{actual.HostConfig.Memory=3221225472;},/actual container\/image\/incarnation mismatch/],
  ['string actual memory',({actual})=>{actual.HostConfig.Memory='2147483648';},/actual container\/image\/incarnation mismatch/],
  ['two actual CPUs',({actual})=>{actual.HostConfig.NanoCpus=2000000000;},/actual container\/image\/incarnation mismatch/],
  ['missing actual environment',({actual})=>{delete actual.Config.Env;},/ModuleShell actual container environment mismatch/],
  ['non-array actual environment',({actual})=>{actual.Config.Env={...moduleEnvironment};},/ModuleShell actual container environment mismatch/],
  ['non-string actual environment',({actual})=>{actual.Config.Env.push(1);},/ModuleShell actual container environment mismatch/],
  ['swapped actual environment values',({actual})=>{
    actual.Config.Env[1]='MAKEPAD_HOME=module-shell-wslc-v1';
    actual.Config.Env[2]='TOOLKIT_MODULE_PROJECT_ID=/tmp/toolkit-module-shell-wslc-home';
  },/ModuleShell actual container environment mismatch/],
];
for (const [index,field] of ['module_shell_makepad_home','module_shell_project_id','module_shell_native_late_probe'].entries()) {
  shellResourceNegatives.push(
    [`missing context ${field}`,({context})=>{delete context[field];},/ModuleShell context environment mismatch/],
    [`foreign context ${field}`,({context})=>{context[field]='foreign';},/ModuleShell context environment mismatch/],
    [`missing creator ${moduleEnvironment[index]}`,({creator})=>{creator.args.splice(11+index*2,2);},/exact owned creator receipt mismatch/],
    [`foreign creator ${moduleEnvironment[index]}`,({creator})=>{creator.args[12+index*2]+='-foreign';},/exact owned creator receipt mismatch/],
    [`missing actual ${moduleEnvironment[index]}`,({actual})=>{actual.Config.Env.splice(index+1,1);},/ModuleShell actual container environment mismatch/],
    [`foreign actual ${moduleEnvironment[index]}`,({actual})=>{actual.Config.Env[index+1]+='-foreign';},/ModuleShell actual container environment mismatch/],
    [`duplicate actual ${moduleEnvironment[index]}`,({actual})=>{actual.Config.Env.push(moduleEnvironment[index]);},/ModuleShell actual container environment mismatch/],
    [`shadowed actual ${moduleEnvironment[index]}`,({actual})=>{actual.Config.Env.push(moduleEnvironment[index]+'-foreign');},/ModuleShell actual container environment mismatch/],
  );
}
for (const [name,mutate,expected] of shellResourceNegatives) {
  test(`synthetic ModuleShell resource graph refuses ${name}`, t => {
    const f = makeFixture(t,{moduleShell:true});
    f.editWitness((w,api)=>editContainerReceipts(w,api,mutate));
    assert.throws(()=>f.verify(),expected);
  });
}

for (const profileKind of [undefined,'FocusFixture']) {
  for (const matchingClaims of [false,true]) {
    test(`${profileKind??'no-kind'} Focus graph refuses 2 GiB ${matchingClaims?'with matching receipt/context claims':'from actual metadata alone'}`, t => {
      const f = makeFixture(t,{profilePatch:profile=>{if(profileKind)profile.profile_kind=profileKind;}});
      f.editWitness((w,api)=>editContainerReceipts(w,api,({context,config,creator,actual})=>{
        actual.HostConfig.Memory=2147483648;
        if (matchingClaims) {
          Object.assign(context,{wslc_profile:'wslc_multi_module',module_shell_profile_kind:'ModuleShell',
            module_shell_source_manifest_sha256:f.contract.source_manifest.sha256,
            memory_max:2147483648,cpus:1,module_instances:2,
            module_shell_makepad_home:'/tmp/toolkit-module-shell-wslc-home',
            module_shell_project_id:'module-shell-wslc-v1',module_shell_native_late_probe:'1'});
          config.profile_kind='ModuleShell';
          config.module_shell={source_manifest_sha256:f.contract.source_manifest.sha256};
          creator.args[6]='2G';creator.args.splice(11,0,...moduleEnvironment.flatMap(value=>['--env',value]));
          actual.Config.Env=[...moduleEnvironment];
        }
      }));
      assert.throws(()=>f.verify(),matchingClaims?/exact owned creator receipt mismatch/:/actual container\/image\/incarnation mismatch/);
    });
  }
}

test('a self-consistently approved staged Main may contain only the recorded path rewrite', t => {
  const f = makeFixture(t,{moduleShell:true,autoCapture:false,
    stagedMainSuffix:'// extra code: pinned hashes alone must not approve this addition\n'});
  assert.throws(()=>f.capture(),/ModuleShell staged source differs beyond approved path substitutions/);
});

const shellBuildNegatives = [
  ['legacy schema masquerading as Shell',({build})=>{build.schema='toolkit-linux-focus-fixture-build-result-v1';},/ModuleShell source-bound build receipt mismatch/],
  ['wrong SDK pin',({build})=>{build.source.SDK_pin='0'.repeat(40);},/ModuleShell source-bound build receipt mismatch/],
  ['failed compiler',({build})=>{build.exit_code=101;},/ModuleShell source-bound build receipt mismatch/],
  ['wrong ELF length',({build})=>{build.artifact.bytes++;},/ModuleShell compiled ELF digest\/length mismatch/],
  ['source changed during build',({build})=>{build.after[0].sha256='F'.repeat(64);},/ModuleShell before\/after source drift/],
  ['missing pinned dependency',({sources})=>{sources.upstream.files.pop();},/ModuleShell upstream source roots missing/],
  ['unarchived Rust source',({sources})=>{sources.compiled.rust_sources.pop();},/ModuleShell required compiled source omitted/],
  ['unrecorded transformation',({sources})=>{sources.transformations.pop();},/ModuleShell path transformations missing/],
  ['foreign module-host path',({sources})=>{sources.transformations[0].replacements[0].to='#[path = "/foreign/module_host.rs"]';},/ModuleShell source path substitution mismatch/],
  ['arbitrary Cargo rewrite',({sources})=>{sources.transformations[1].replacements[0].from='name = "toolkit-app-module-shell"';},/ModuleShell Cargo transform is not an approved upstream path/],
  ['wrong toolchain target',({build})=>{build.toolchain.target='aarch64-unknown-linux-gnu';},/ModuleShell toolchain\/target observation missing/],
  ['missing rustc identity',({build})=>{build.toolchain.rustc_vv='rustc unknown';},/ModuleShell toolchain\/target observation missing/],
  ['unlocked build',({build})=>{build.cargo.args=build.cargo.args.filter(a=>a!=='--locked');},/ModuleShell Cargo must be exact locked\/offline sequential invocation/],
  ['online build',({build})=>{build.cargo.args=build.cargo.args.filter(a=>a!=='--offline');},/ModuleShell Cargo must be exact locked\/offline sequential invocation/],
  ['parallel build',({build})=>{build.cargo.args[8]='2';},/ModuleShell Cargo must be exact locked\/offline sequential invocation/],
  ['native timeout',({native})=>{native.timed_out=true;},/ModuleShell native compiler receipt missing/],
  ['undrained native result',({native})=>{native.output_drained=false;},/ModuleShell native compiler receipt missing/],
  ['foreign native receipt',({build})=>{build.receipt='other-native.json';},/ModuleShell build\/native receipt join mismatch/],
  ['foreign native harness',({native})=>{native.args[5]='/foreign/build.sh';},/ModuleShell actual build harness invocation mismatch/],
  ['missing actual command',({native})=>{native.stdout=native.stdout.split('\n').filter(l=>!l.startsWith('TOOLKIT_MODULE_SHELL_COMMAND ')).join('\n');},/ModuleShell actual COMMAND observation missing\/mismatch/],
  ['duplicate actual command',({native})=>{native.stdout+='\n'+native.stdout.split('\n').find(l=>l.startsWith('TOOLKIT_MODULE_SHELL_COMMAND '));},/ModuleShell actual COMMAND observation missing\/mismatch/],
  ['source observation after build',({native})=>{
    const lines=native.stdout.split('\n'),before=lines.find(l=>l.startsWith('TOOLKIT_MODULE_SHELL_BEFORE '));
    native.stdout=lines.filter(l=>l!==before).concat(before).join('\n');
  },/ModuleShell native build observation order mismatch/],
  ['truncated actual source observation',({native})=>{native.stdout=native.stdout.replace(/TOOLKIT_MODULE_SHELL_BEFORE [^\n]*/,'TOOLKIT_MODULE_SHELL_BEFORE {');},/invalid\/truncated\/UTF-8 identity JSON/],
  ['compiler target from another crate',({native})=>{native.stdout=native.stdout.replace('"name":"toolkit-app-module-shell"','"name":"foreign-crate"');},/ModuleShell actual compiled ELF\/source receipt join missing/],
  ['actual source byte tampering',({sources,write})=>{write(sources.compiled.cargo_lock.path,'different actual bytes\n');},/ModuleShell actual input bytes changed\/duplicated/],
  ['source archive path escape',({sources})=>{sources.files[0].path='../outside.rs';},/unsafe provenance path/],
];
for(const [name,shellPatch,expected] of shellBuildNegatives) {
  test(`ModuleShell beginRun refuses ${name}`,t=>{
    const f=makeFixture(t,{moduleShell:true,autoCapture:false,shellPatch});
    assert.throws(()=>f.capture(),expected);
  });
}

test('profile-kind dispatch cannot silently select another build contract',t=>{
  const unknown=makeFixture(t,{autoCapture:false,profilePatch:p=>{p.profile_kind='Unknown';}});
  assert.throws(()=>unknown.capture(),/unknown approved artifact profile kind/);
  const wrong=makeFixture(t,{autoCapture:false,profilePatch:p=>{p.profile_kind='ModuleShell';}});
  assert.throws(()=>wrong.capture(),/ModuleShell source set not approved by trusted profile/);
});

const shellRuntimeNegatives = [
  ['wrong container CID',w=>{w.container.container_id='f'.repeat(64);},/container ownership identity mismatch/],
  ['wrong image',w=>{w.container.image_id='sha256:'+'f'.repeat(64);},/container ownership identity mismatch/],
  ['different incarnation',(w,api)=>{
    const context=api.readRef(w.context);context.exclusive_nonce='f'.repeat(32);
    w.context=api.writeRef(w.context,context);
  },/container incarnation mismatch/],
  ['missing transfer',w=>{delete w.transfer_receipt;},/missing immutable receipt reference/],
  ['foreign transfer incarnation',(w,api)=>{
    const transfer=api.readRef(w.transfer_receipt);transfer.provenance.container.nonce='f'.repeat(32);
    w.transfer_receipt=api.writeRef(w.transfer_receipt,transfer);
  },/transfer reused for another container\/owner incarnation/],
  ['host changed during transfer',(w,api)=>{
    const transfer=api.readRef(w.transfer_receipt);transfer.provenance.source.sha256_after='F'.repeat(64);
    w.transfer_receipt=api.writeRef(w.transfer_receipt,transfer);
  },/host changed during transfer/],
  ['wrong transferred guest ELF',(w,api)=>{
    const transfer=api.readRef(w.transfer_receipt);transfer.provenance.guest.sha256='F'.repeat(64);
    w.transfer_receipt=api.writeRef(w.transfer_receipt,transfer);
  },/transferred guest ELF byte mismatch/],
  ['missing process birth',w=>{
    const k=JSON.parse(w.raw_kernel_report_utf8);k.before.proc_stat_raw='';
    w.raw_kernel_report_utf8=JSON.stringify(k);w.raw_kernel_report_sha256=hash(w.raw_kernel_report_utf8);
    w.collector_invocation.stdout_sha256=w.raw_kernel_report_sha256;
  },/missing \/proc stat/],
  ['different running executable',w=>{
    const k=JSON.parse(w.raw_kernel_report_utf8);k.after.exe_link='/foreign/other-elf';
    w.raw_kernel_report_utf8=JSON.stringify(k);w.raw_kernel_report_sha256=hash(w.raw_kernel_report_utf8);
    w.collector_invocation.stdout_sha256=w.raw_kernel_report_sha256;
  },/deleted\/replaced \/proc executable/],
  ['unbound launch nonce',w=>{w.launch_binding.launch_nonce='f'.repeat(32);},/observed process not bound to owned launch/],
  ['unbound parent birth',w=>{w.launch_binding.parent_birth='600001';},/observed process not bound to owned launch/],
  ['foreign session',w=>{w.session_id='foreign-synthetic-session';},/cross-session\/owner\/generation mismatch/],
  ['foreign generation',w=>{w.generation++;},/cross-session\/owner\/generation mismatch/],
  ['foreign listener',w=>{
    const k=JSON.parse(w.raw_kernel_report_utf8);k.listener.socket_fd_link='socket:[999]';
    w.raw_kernel_report_utf8=JSON.stringify(k);w.raw_kernel_report_sha256=hash(w.raw_kernel_report_utf8);
    w.collector_invocation.stdout_sha256=w.raw_kernel_report_sha256;
  },/listener FD owner mismatch/],
];
for(const [name,edit,expected] of shellRuntimeNegatives) {
  test(`ModuleShell keeps full Core runtime refusal for ${name}`,t=>{
    const f=makeFixture(t,{moduleShell:true});f.editWitness(edit);
    assert.throws(()=>f.verify(),expected);
  });
}

test('verifyEvidence rejects an empty raw provenance index', t => {
  const f = makeFixture(t);
  f.editObservation(observation => { observation.raw_provenance = []; });
  assert.throws(() => f.verify(), /IDENTITY_NOT_VERIFIED: missing WSLC raw evidence index/);
});

test('verifyEvidence rejects an indexed witness changed after finish without resealing', t => {
  const f = makeFixture(t);
  fs.appendFileSync(path.join(f.root, f.witnessPath), ' \n');
  assert.throws(() => f.verify(), /IDENTITY_MISMATCH: raw producer evidence changed or duplicated/);
});

test('beginRun rejects a host SHA that differs from the bounded host bytes', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    contractPatch: c => { c.sha256 = 'F'.repeat(64); },
  });
  assert.throws(() => f.capture(), /approved host bytes changed/);
});

test('beginRun rejects an approved artifact size mismatch', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    contractPatch: c => { c.bytes += 1; },
  });
  assert.throws(() => f.capture(), /approved host bytes changed/);
});

test('beginRun/finishRun reject equal-byte host replacement after approval', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    afterBeginRun: ({root, artifactPath, hostBytes}) => {
      const approvedPath = path.join(root, artifactPath);
      const retainedOriginal = path.join(root, 'artifacts/focus-fixture.pre-replacement.elf');
      fs.renameSync(approvedPath, retainedOriginal);
      fs.writeFileSync(approvedPath, hostBytes);
    },
  });
  const renameProbe = path.join(f.root, 'artifacts/rename-permission-probe');
  fs.writeFileSync(renameProbe, 'synthetic rename probe');
  try {
    fs.renameSync(renameProbe, renameProbe + '.moved');
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') {
      t.skip('host filesystem permission denied same-directory replacement');
      return;
    }
    throw error;
  }
  assert.throws(() => f.capture(), /host artifact identity changed during run/);
});

test('verifyEvidence rejects a guest SHA mismatch in the immutable source-bound transfer receipt', t => {
  const f = makeFixture(t);
  f.editWitness((w, api) => {
    const transfer = api.readRef(w.transfer_receipt);
    transfer.provenance.guest.sha256 = 'F'.repeat(64);
    w.transfer_receipt = api.writeRef(w.transfer_receipt, transfer);
  });
  assert.throws(() => f.verify(), /transferred guest ELF byte mismatch/);
});

test('verifyEvidence rejects a guest byte count mismatch', t => {
  const f = makeFixture(t);
  f.editWitness((w, api) => {
    const transfer = api.readRef(w.transfer_receipt);
    transfer.provenance.guest.bytes += 1;
    w.transfer_receipt = api.writeRef(w.transfer_receipt, transfer);
  });
  assert.throws(() => f.verify(), /transferred guest ELF byte mismatch/);
});

test('verifyEvidence rejects a transfer receipt with an incomplete host FD identity', t => {
  const f = makeFixture(t);
  f.editWitness((w, api) => {
    const transfer = api.readRef(w.transfer_receipt);
    delete transfer.provenance.source.fd_before.volume_serial;
    delete transfer.provenance.source.fd_after.volume_serial;
    w.transfer_receipt = api.writeRef(w.transfer_receipt, transfer);
  });
  assert.throws(() => f.verify(), /IDENTITY_NOT_VERIFIED: incomplete actual host transfer FD identity/);
});

test('verifyEvidence rejects an unapproved container ID and explicit inspect privilege', t => {
  const f = makeFixture(t);
  f.editWitness(w => { w.container.container_id = 'f'.repeat(64); });
  assert.throws(() => f.verify(), /container ownership identity mismatch/);

  for (const privileged of [true, 0]) {
    f.editWitness((w, api) => {
      w.container.container_id = f.containerId;
      const transfer = api.readRef(w.transfer_receipt);
      const inspectRef = transfer.provenance.container_inspect_receipt;
      const inspectReceipt = api.readRef(inspectRef);
      const inspected = JSON.parse(inspectReceipt.stdout);
      inspected[0].HostConfig.Privileged = privileged;
      inspectReceipt.stdout = JSON.stringify(inspected);
      transfer.provenance.container_inspect_receipt = api.writeRef(inspectRef, inspectReceipt);
      w.transfer_receipt = api.writeRef(w.transfer_receipt, transfer);
    });
    assert.throws(() => f.verify(), /explicit privileged\/unknown container mode refused/);
  }
});

test('verifyEvidence rejects an unapproved container image ID', t => {
  const f = makeFixture(t);
  f.editWitness(w => { w.container.image_id = 'sha256:' + 'c'.repeat(64); });
  assert.throws(() => f.verify(), /container ownership identity mismatch/);
});

test('verifyEvidence rejects container incarnation drift', t => {
  const f = makeFixture(t);
  f.editWitness((w, api) => {
    const context = api.readRef(w.context);
    context.container_created = '2026-01-01T00:00:00.000Z';
    const contextRef = api.writeRef(w.context, context);
    w.context = contextRef;
    const transfer = api.readRef(w.transfer_receipt);
    transfer.provenance.context = contextRef;
    w.transfer_receipt = api.writeRef(w.transfer_receipt, transfer);
  });
  assert.throws(() => f.verify(), /container incarnation mismatch/);
});

test('verifyEvidence rejects a container ownership nonce mismatch', t => {
  const f = makeFixture(t);
  f.editWitness((w, api) => {
    const context = api.readRef(w.context);
    context.exclusive_nonce = 'e'.repeat(32);
    const contextRef = api.writeRef(w.context, context);
    w.context = contextRef;
    const transfer = api.readRef(w.transfer_receipt);
    transfer.provenance.context = contextRef;
    w.transfer_receipt = api.writeRef(w.transfer_receipt, transfer);
  });
  assert.throws(() => f.verify(), /container incarnation mismatch/);
});

test('verifyEvidence rejects a process birth identity mismatch', t => {
  const f = makeFixture(t);
  f.editObservation(observation => {
    observation.runtime.process_start_ticks = '700001';
  });
  assert.throws(() => f.verify(), /PID reuse\/process birth\/parent mismatch/);
});

test('verifyEvidence rejects a missing proc stat witness', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    kernel.before.proc_stat_raw = '';
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /missing \/proc stat/);
});

test('verifyEvidence rejects a missing raw process birth time', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    kernel.before.proc_stat_raw = procStat(4242, 'focus-fixture', 'S', 4000, '');
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /OUTCOME_UNKNOWN: invalid\/dead process observation/);
});

test('verifyEvidence rejects a transfer receipt reused from another owner context', t => {
  const f = makeFixture(t);
  f.editWitness((w, api) => {
    const transfer = api.readRef(w.transfer_receipt);
    const priorContext = api.readRef(w.context);
    priorContext.exclusive_nonce = 'f'.repeat(32);
    const priorContextRef = api.writeRef(
      {path: 'receipts/prior-owner-context.json'},
      priorContext,
    );
    transfer.provenance.operation_id = '00000000-0000-4000-8000-000000000002';
    transfer.provenance.context = priorContextRef;
    w.transfer_receipt = api.writeRef(w.transfer_receipt, transfer);
  });
  assert.throws(() => f.verify(), /transfer reused for another container\/owner incarnation/);
});

test('verifyEvidence rejects a missing immutable transfer reference', t => {
  const f = makeFixture(t);
  f.editWitness(w => { delete w.transfer_receipt; });
  assert.throws(() => f.verify(), /IDENTITY_NOT_VERIFIED: missing immutable receipt reference/);
});

test('verifyEvidence rejects a truncated immutable receipt reference', t => {
  const f = makeFixture(t);
  f.editWitness((w, api) => {
    w.context = api.writeRef(w.context, Buffer.from('{"container_id":', 'utf8'));
  });
  assert.throws(() => f.verify(), /invalid\/truncated\/UTF-8 identity JSON/);
});

test('beginRun rejects a source manifest hash that does not match its pinned bytes', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    contractPatch: c => { c.source_manifest.sha256 = 'F'.repeat(64); },
  });
  assert.throws(() => f.capture(), /receipt byte digest mismatch/);
});

test('beginRun rejects a source commit that differs from the pinned profile policy', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    profilePatch: profile => { profile.source_commit = '0'.repeat(40); },
  });
  assert.throws(() => f.capture(), /untrusted WSLC profile/);
});

test('beginRun rejects a WSLC profile without explicit experimental opt-in', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    profilePatch: profile => { delete profile.experimental_opt_in; },
  });
  assert.throws(() => f.capture(), /untrusted WSLC profile/);
});

test('beginRun rejects a provenance path escaping the consumer root', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    contractPatch: c => { c.host_path = '../outside/focus-fixture.elf'; },
  });
  assert.throws(() => f.capture(), /unsafe provenance path/);
});

test('beginRun rejects a Windows extended local-drive reference escaping the consumer root', t => {
  if (process.platform !== 'win32') {
    t.skip('Windows extended local-drive paths are platform-specific');
    return;
  }
  const f = makeFixture(t, {
    autoCapture: false,
    contractPatch: (c, {root}) => {
      c.host_path = '\\\\?\\' + path.resolve(root, '..', 'outside-wslc-fixture.elf');
    },
  });
  assert.throws(() => f.capture(), /provenance path escapes project/);
});

test('Core provenance path rejects symlink ancestry when the host permits creating one', t => {
  const root = temporaryRoot(t);
  const targetDir = path.join(root, 'target');
  fs.mkdirSync(targetDir);
  fs.writeFileSync(path.join(targetDir, 'payload.bin'), 'synthetic payload');
  const symlinkDir = path.join(root, 'linked-target');
  try {
    fs.symlinkSync(targetDir, symlinkDir, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') {
      t.skip('host filesystem permission denied symlink creation');
      return;
    }
    throw error;
  }
  assert.throws(
    () => provenancePath(root, 'linked-target/payload.bin'),
    /reparse\/symlink refused/,
  );
});

test('Core host observation rejects a hard-linked file', t => {
  const root = temporaryRoot(t);
  const targetDir = path.join(root, 'target');
  fs.mkdirSync(targetDir);
  fs.writeFileSync(path.join(targetDir, 'payload.bin'), 'synthetic payload');
  const hardlink = path.join(root, 'hardlinked-payload.bin');
  try {
    fs.linkSync(path.join(targetDir, 'payload.bin'), hardlink);
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') {
      t.skip('host filesystem permission denied hard-link creation');
      return;
    }
    throw error;
  }
  assert.throws(
    () => observeHostFile(root, 'hardlinked-payload.bin'),
    /nonregular, linked or unbounded host artifact/,
  );
});

test('beginRun rejects duplicate keys in a raw native compiler receipt', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    nativeReceiptBytes: Buffer.from(
      '{"exit_code":0,"exit_code":0,"timed_out":false,"output_drained":true,"executable":"C:/Windows/System32/wsl.exe","args":[],"stdout":""}\n',
      'utf8',
    ),
  });
  assert.throws(() => f.capture(), /duplicate identity JSON key/);
});

test('beginRun rejects invalid UTF-8 in a raw native compiler receipt', t => {
  const f = makeFixture(t, {
    autoCapture: false,
    nativeReceiptBytes: Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]),
  });
  assert.throws(() => f.capture(), /invalid\/truncated\/UTF-8 identity JSON/);
});

test('beginRun rejects excessive JSON nesting in an immutable receipt', t => {
  let deeplyNested = '0';
  for (let i = 0; i < 70; i++) deeplyNested = '{"x":' + deeplyNested + '}';
  const f = makeFixture(t, {
    autoCapture: false,
    nativeReceiptBytes: Buffer.from(deeplyNested, 'utf8'),
  });
  assert.throws(() => f.capture(), /JSON nesting bound/);
});

test('verifyEvidence rejects a stale provenance time window', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    w.started_utc = new Date(Date.parse(f.run.started_at) - 60_000).toISOString();
  });
  assert.throws(() => f.verify(), /stale\/reused\/out-of-order provenance/);
});

test('verifyEvidence rejects executable file identity replacement after spawn', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    kernel.after.executable_fd_stat.inode = '900002';
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /post-spawn executable replacement\/file hash race/);
});

test('verifyEvidence rejects a raw guest executable hash mismatch', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    kernel.guest_path_fd_sha256 = 'F'.repeat(64);
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /running ELF differs from approved bytes/);
});

test('verifyEvidence rejects a listener inode observed for another process', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    const fields = kernel.listener.proc_net_tcp_row.trim().split(/\s+/);
    fields[9] = '987654';
    kernel.listener.proc_net_tcp_row = fields.join(' ');
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /actual listener kernel row mismatch/);
});

test('verifyEvidence reports an app exit observed during verification as unknown outcome', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    kernel.after.proc_stat_raw = procStat(4242, 'focus-fixture', 'Z', 4000, '700000');
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /OUTCOME_UNKNOWN: invalid\/dead process observation/);
});

test('verifyEvidence rejects a witness from another owner session', t => {
  const f = makeFixture(t);
  f.editWitness(w => { w.session_id = 'different-synthetic-session'; });
  assert.throws(() => f.verify(), /cross-session\/owner\/generation mismatch/);
});

test('verifyEvidence rejects a stale policy digest retained in the plan', t => {
  const f = makeFixture(t);
  f.policy.budgets.typical_gui_runs += 1;
  assert.throws(() => f.verify(), /stale policy\/global binding or forged plan/);
});

test('verifyEvidence rejects an unrecognized raw-kernel collector executable', t => {
  const f = makeFixture(t);
  f.editWitness(w => { w.collector_invocation.executable = 'C:\\Program Files\\WSL\\other.exe'; });
  assert.throws(() => f.verify(), /raw kernel report not bound to trusted collector invocation/);
});

test('verifyEvidence rejects collector arguments that do not bind the frozen program and target', t => {
  const f = makeFixture(t);
  f.editWitness(w => { w.collector_invocation.args[4] = '# different synthetic program'; });
  assert.throws(() => f.verify(), /raw kernel report not bound to trusted collector invocation/);
});

test('verifyEvidence rejects a kernel observation outside the collector host-time bounds', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    kernel.observed_start_unix_ns = String(BigInt(w.collector_invocation.started_unix_ns) - 3_000_000_000n);
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /stale\/partial guest kernel observation/);
});

test('verifyEvidence rejects a changed raw parent proc-stat recheck', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    kernel.parent.after_proc_stat_raw = procStat(4000, 'timeout', 'S', 1, '600001');
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /parent changed during executable verification/);
});

test('verifyEvidence rejects changed raw parent argv after the kernel observation', t => {
  const f = makeFixture(t);
  f.editWitness(w => {
    const kernel = JSON.parse(w.raw_kernel_report_utf8);
    kernel.parent.argv_after[0] = 'other-launcher';
    w.raw_kernel_report_utf8 = JSON.stringify(kernel);
    w.raw_kernel_report_sha256 = hash(Buffer.from(w.raw_kernel_report_utf8, 'utf8'));
    w.collector_invocation.stdout_sha256 = w.raw_kernel_report_sha256;
  });
  assert.throws(() => f.verify(), /parent changed during executable verification/);
});
for(const moduleShell of [false,true])test(`actual launch budget remains profile-specific (ModuleShell=${moduleShell})`,t=>{
  const f=makeFixture(t,{moduleShell});
  f.editWitness(w=>{
    const k=JSON.parse(w.raw_kernel_report_utf8),wrong=moduleShell?'300s':'660s';
    k.parent.argv[3]=wrong;k.parent.argv_after[3]=wrong;w.launch_binding.parent_argv[3]=wrong;
    w.raw_kernel_report_utf8=JSON.stringify(k);w.raw_kernel_report_sha256=hash(Buffer.from(w.raw_kernel_report_utf8));
    w.collector_invocation.stdout_sha256=w.raw_kernel_report_sha256;
  });
  assert.throws(()=>f.verify(),/foreign launcher command/);
});

test('observeHostFile returns captured bytes and digest from the same bounded file observation', t => {
  const root = temporaryRoot(t);
  const payload = Buffer.from('synthetic same-FD capture');
  fs.writeFileSync(path.join(root, 'payload.bin'), payload);
  const observed = observeHostFile(root, 'payload.bin', {capture: true});
  assert.deepEqual(observed.content, payload);
  assert.equal(observed.sha256, hash(payload));
  assert.equal(observed.bytes, payload.length);
});

// Synthetic operator envelopes exercise the ordinary Core planner/begin/verify
// path. They do not attest a RAM measurement or an executed Linux process.
function operatorWaiverInput(f) {
  const utc=new Date().toISOString(),profile=f.read(f.profilePath),source=f.contract.source_manifest.sha256;
  const receiptPath='receipts/operator-ram.json';
  const native={schema:'toolkit-makepad-dev-app-module-shell-host-admission-v1',utc,owner:f.owner,
    source_manifest_sha256:source,host_ram_mode:'USER_WAIVED',status:'USER_WAIVED',available_memory_query_performed:false,
    minimum_free_bytes:2684354560,minimum_free_kib:2621440,container_memory_bytes:2147483648,container_cpus:1,nested_increment_kib:0,
    active_compiler_observation_performed:true,active_rust_compilers:[],resource_admitted:false,scope:'one_outer_runtime_admission'};
  f.write(receiptPath,native);
  const available={...allResources};delete available.available_ram_mib;
  available.host_runtime_budget_mib=2560;
  available.ram_admission={schema:'toolkit-module-shell-core-ram-waiver-v1',status:'USER_WAIVED',
    receipt:{path:receiptPath,sha256:f.h(receiptPath)},profile:f.contract.profile,utc,checked_at:utc,owner:f.owner,
    source_manifest_sha256:source,available_memory_query_performed:false,resource_admitted:false,
    container_memory_bytes:2147483648,container_cpus:1,nested_increment_kib:0};
  return {...f.plan.planning_input,trusted_root:f.root,available_resources:available};
}
test('operator RAM waiver is source/profile/receipt bound through actual Core plan and begin',t=>{
  const f=makeFixture(t,{moduleShell:true,autoCapture:false}),input=operatorWaiverInput(f);
  assert.equal(resourceAdmission(f.plan.resource_requirements,input.available_resources).status,'BLOCKED_ENVIRONMENT');
  const plan=planProject(f.policy,input);assert.equal(plan.status,'PLANNED');
  assert.equal(plan.resource_admission.operator_ram.available_memory_observed,false);
  assert.equal(plan.resource_admission.operator_ram.status,'USER_WAIVED');
  assert.deepEqual(plan.resource_admission.waived_blockers,['insufficient_available_ram']);
  const frozen=f.read(f.freezePath);frozen.push(input.available_resources.ram_admission.receipt);f.write(f.freezePath,frozen);
  const run=beginRun(f.root,f.policy,plan,scenarioId,f.freezePath);
  assert.deepEqual(run.operator_ram_admission,plan.resource_admission.operator_ram);
});
test('operator RAM waiver cannot authorize FocusFixture or missing/foreign/profile/source receipts',t=>{
  const focus=makeFixture(t,{autoCapture:false});assert.throws(()=>planProject(focus.policy,operatorWaiverInput(focus)),/operator RAM/);
  for(const kind of ['missing-root','foreign-owner','wrong-source','wrong-profile','fake-free-ram','active-compiler','bytes-changed']){
    const f=makeFixture(t,{moduleShell:true,autoCapture:false}),input=operatorWaiverInput(f),a=input.available_resources.ram_admission;
    if(kind==='missing-root')delete input.trusted_root;
    if(kind==='foreign-owner')a.owner='foreign';
    if(kind==='wrong-source')a.source_manifest_sha256='A'.repeat(64);
    if(kind==='wrong-profile')a.profile={...a.profile,sha256:'A'.repeat(64)};
    if(kind==='fake-free-ram')input.available_resources.available_ram_mib=4096;
    if(kind==='active-compiler'){const doc=f.read(a.receipt.path);doc.active_rust_compilers=[123];f.write(a.receipt.path,doc);a.receipt.sha256=f.h(a.receipt.path);}
    if(kind==='bytes-changed')fs.appendFileSync(path.join(f.root,a.receipt.path),'\n');
    assert.throws(()=>planProject(f.policy,input),undefined,kind);
  }
});
test('operator RAM waiver refuses stale dispatch, unfrozen receipt and unrelated resource blockers',t=>{
  const f=makeFixture(t,{moduleShell:true,autoCapture:false}),input=operatorWaiverInput(f);
  let bad=structuredClone(input);bad.available_resources.wslc_session=false;
  assert.throws(()=>planProject(f.policy,bad),/another resource blocker/);
  bad=structuredClone(input);bad.available_resources.heavy_workloads_active=1;
  assert.throws(()=>planProject(f.policy,bad),/another resource blocker/);
  const plan=planProject(f.policy,input);
  assert.throws(()=>beginRun(f.root,f.policy,plan,scenarioId,f.freezePath),/must be frozen/);
  const frozen=f.read(f.freezePath);frozen.push(input.available_resources.ram_admission.receipt);f.write(f.freezePath,frozen);
  const original=Date.now;Date.now=()=>Date.parse(input.available_resources.ram_admission.utc)+120001;
  try{assert.throws(()=>beginRun(f.root,f.policy,plan,scenarioId,f.freezePath),/not fresh before dispatch/);}finally{Date.now=original;}
});
test('operator RAM waiver verifies the full Core evidence graph while memory remains explicitly unmeasured',t=>{
  const f=makeFixture(t,{moduleShell:true,autoCapture:false}),input=operatorWaiverInput(f);
  f.plan=planProject(f.policy,input);
  const frozen=f.read(f.freezePath);frozen.push(input.available_resources.ram_admission.receipt);f.write(f.freezePath,frozen);
  const quality=f.read('quality.json');quality.source_freeze_sha256=f.h(f.freezePath);
  quality.available_resources=input.available_resources;f.write('quality.json',quality);
  f.capture();
  const accepted=f.verify();assert.equal(accepted.verified_proof,true);
  assert.equal(f.run.operator_ram_admission.available_memory_observed,false);
  const saved=f.read(f.runPath);saved.operator_ram_admission.owner='foreign';f.write(f.runPath,saved);
  assert.throws(()=>f.verify(),/operator RAM run\/root\/receipt binding mismatch/);
});
