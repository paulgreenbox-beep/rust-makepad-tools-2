"""Source contracts and isolated PowerShell decisions; never runs the bootstrap.

Decision tests extract its fixture parameters/selection, font contract/listing, creator guard, startup
approval slice and failure catch with the PowerShell parser. Receipt reads/writes and capture are in-memory
mocks: no WSLC,
inventory, ELF copy, App, relay, native GUI or bootstrap top-level execution.
"""

import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest


HERE = Path(__file__).parent
BOOTSTRAP = (HERE / "bootstrap-runtime.ps1").read_text(encoding="utf-8")
UPLOAD = (HERE / "upload-artifact.ps1").read_text(encoding="utf-8")
CLEANUP = (HERE / "cleanup-runtime.ps1").read_text(encoding="utf-8")
PIN = "71c9ddcbb9c01dd208f99621fdd71024a5d35c65"
IMAGE = "sha256:219e68c9b9ff3c0e24f8a2e937abe08beb98ebd2c88d551f25f09b052ff2107b"
ELF = "C989BFA10615A839B61A2D6D8D4D7C04501CC7B62559241A32846D53BC5DC48C"
FOCUS_ELF = "9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB"
AUTHORIZATION_UTF8 = '''{
  "schema": "toolkit-scoped-operator-resource-authorization-v1",
  "milestone": "MAKEPAD_DEV_REMOTE_API_ADOPTION_V1",
  "operator_quote": "Игнорируй нехваток памяти",
  "authorization_source": "current human message in this Codex thread",
  "thread_id": "01a00532-be65-7723-89ec-c1b2bfdd373e",
  "scope": "RAM-only admission exception for continuing this milestone; not a global policy change",
  "permitted": ["serial bounded owning tests and CLI build", "serial bounded required runtime proof"],
  "retained_guards": ["no overlapping heavy workloads", "Cargo -j 1", "bounded timeout", "exact owned process identity", "evidence and cleanup", "no foreign process termination", "WSLC 1 GiB and 1 CPU limits"],
  "actual_memory_observation_required": true,
  "stock_admission_results_must_not_be_relabelled": true,
  "global_resource_policy_changed": false,
  "historical_blockage_superseded_by_new_authorization": "blocked-audit-28.json",
  "runtime_acceptance_claimed": false
}
'''


class BootstrapRemoteContractTests(unittest.TestCase):
    def test_actual_relay_budget_is_opt_in_and_bound_to_the_approved_module_context(self):
        script = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__RELAY__',[ref]$tokens,[ref]$errors)
$f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-RelayRuntimeBudget'},$true))
if(@($errors).Count -or $f.Count -ne 1){throw 'Actual relay budget guard missing'}
. ([scriptblock]::Create($f[0].Extent.Text))
$cid='a'*64
$valid=@{container_id=$cid;runtime_profile='makepad_remote71';wslc_profile='wslc_multi_module';module_shell_profile_kind='ModuleShell';
 module_shell_source_manifest_sha256='91F63101687B7BFB778391AB780BCF5AF1B8697D3DA81B5E08E70FFF39C32E42';
 fixture_sha256='F7B286EF5A851028BA631A690ED0CE2FC3D4F71F91E0097BA28A7F71DDC93489';owns_container=$true;owns_vm=$false;
 memory_max=2147483648;cpus=1;module_instances=2}
$r=@{}
foreach($name in @('legacy360','legacy600','legacy601','legacy720','module720','module600','missing','cid','source','elf','memory','cpu','cpu_bool','foreign_vm','unowned')){
 $ctx=$valid.Clone();$seconds=720;$module=$true;$id=$cid
 switch($name){
 legacy360 {$module=$false;$seconds=360}
 legacy600 {$module=$false;$seconds=600}
 legacy601 {$module=$false;$seconds=601}
 legacy720 {$module=$false}
 module600 {$seconds=600}
 missing {$ctx=$null}
 cid {$id='b'*64}
 source {$ctx.module_shell_source_manifest_sha256='B'*64}
 elf {$ctx.fixture_sha256='B'*64}
 memory {$ctx.memory_max=1073741824}
 cpu {$ctx.cpus=2}
 cpu_bool {$ctx.cpus=$true}
 foreign_vm {$ctx.owns_vm=$true}
 unowned {$ctx.owns_container=$false}
 }
 try{Assert-RelayRuntimeBudget $seconds $module $ctx $id;$r[$name]=$true}catch{$r[$name]=$false}
}
$r|ConvertTo-Json -Compress
'''.replace('__RELAY__',str(HERE/'stdio-relay.ps1').replace("'","''"))
        result=subprocess.run([shutil.which('pwsh'),'-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        decisions=json.loads(result.stdout)
        for case,accepted in decisions.items():self.assertEqual(accepted,case in ('legacy360','legacy600','module720'),case)

    def test_actual_module_cleanup_avoids_host_ram_query_and_retains_legacy_observation(self):
        script = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__CLEANUP__',[ref]$tokens,[ref]$errors)
$guard=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text -ceq "$context.module_shell_profile_kind -ceq 'ModuleShell'"},$true))
'''.replace('"$context.module_shell_profile_kind', '"`$context.module_shell_profile_kind') + r'''
if(@($errors).Count -or $guard.Count -ne 1){throw 'Actual cleanup branch missing'}
$code=[scriptblock]::Create($guard[0].Extent.Text);$script:queries=0
function Get-CimInstance($Class){$script:queries++;return @{FreePhysicalMemory=12345}}
$context=@{module_shell_profile_kind='ModuleShell'};$record=[ordered]@{};& $code
if($script:queries -ne 0 -or $record.available_memory_query_performed -ne $false -or $record.host_ram_mode -cne 'USER_WAIVED' -or $record.Contains('free_physical_kib')){throw 'Module queried host RAM'}
$context=@{};$record=[ordered]@{};& $code
if($script:queries -ne 1 -or $record.free_physical_kib -ne 12345){throw 'Legacy observation changed'}
'''
        script = script.replace('__CLEANUP__', str(HERE/'cleanup-runtime.ps1').replace("'", "''"))
        result = subprocess.run([shutil.which('pwsh'), '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_actual_module_uploader_admission_joins_fresh_owner_source_and_compiler_observation(self):
        script = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__UPLOAD__',[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'Parse failed'}
$guards=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text.StartsWith('$hostAdmission.Count -ne 16')},$true))
$age=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and
 $n.Left.Extent.Text -ceq '$admissionAge'},$true))
if($guards.Count -ne 1 -or $age.Count -ne 1){throw 'Actual uploader admission guard missing'}
$guard=[scriptblock]::Create($age[0].Extent.Text+"`n"+$guards[0].Extent.Text)
$valid=[ordered]@{schema='toolkit-makepad-dev-app-module-shell-host-admission-v1';utc=[DateTimeOffset]::UtcNow.ToString('o');
 owner='owned';source_manifest_sha256=('A'*64);host_ram_mode='USER_WAIVED';status='USER_WAIVED';
 available_memory_query_performed=$false;minimum_free_bytes=2684354560;minimum_free_kib=2621440;
 container_memory_bytes=2147483648;container_cpus=1;nested_increment_kib=0;active_compiler_observation_performed=$true;
 active_rust_compilers=@();resource_admitted=$false;scope='one_outer_runtime_admission'}
$out=[ordered]@{}
foreach($case in @('valid','owner','source','stale','future','compiler','compiler_missing','query','extra','budget')){
 $hostAdmission=[ordered]@{};foreach($key in $valid.Keys){$hostAdmission[$key]=$valid[$key]}
 switch($case){
 owner {$hostAdmission.owner='foreign'}
 source {$hostAdmission.source_manifest_sha256='B'*64}
 stale {$hostAdmission.utc=[DateTimeOffset]::UtcNow.AddMinutes(-3).ToString('o')}
 future {$hostAdmission.utc=[DateTimeOffset]::UtcNow.AddMinutes(1).ToString('o')}
 compiler {$hostAdmission.active_rust_compilers=@('rustc.exe')}
 compiler_missing {$hostAdmission.Remove('active_compiler_observation_performed')}
 query {$hostAdmission.available_memory_query_performed=$true}
 extra {$hostAdmission.free_physical_kib=99999999}
 budget {$hostAdmission.container_memory_bytes=1073741824}
 }
 $uploadContext=@{exclusive_owner='owned'};$moduleShellApproval=@{source_manifest=@{sha256=('A'*64)}}
 try{& $guard;$out[$case]=$true}catch{$out[$case]=$false}
}
$out|ConvertTo-Json -Compress
'''.replace('__UPLOAD__', str(HERE / 'upload-artifact.ps1').replace("'", "''"))
        result = subprocess.run([shutil.which('pwsh'), '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        decisions = json.loads(result.stdout)
        self.assertTrue(decisions.pop('valid'))
        self.assertFalse(any(decisions.values()), decisions)

    def test_actual_stage_size_guard_preserves_legacy_cap_and_requires_exact_module_length(self):
        script = r'''
$ErrorActionPreference='Stop';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__BOOTSTRAP__',[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'Parse failed'}
$guards=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text.StartsWith('$fixtureStream.Length -le 0')},$true))
if($guards.Count -ne 1){throw 'Actual staging size guard missing'}
$guard=[scriptblock]::Create($guards[0].Extent.Text)
function Accepted([long]$Length,[long]$Observed,[bool]$Module,[long]$Approved){
 $fixtureStream=@{Length=$Length};$before=@{Length=$Observed};$multiModuleProfile=$Module
 $moduleShellApproval=if($Approved -gt 0){@{artifact=@{bytes=$Approved}}}else{$null}
 try{& $guard;return $true}catch{if($_.Exception.Message -cne 'APPROVED_ELF_SIZE_REFUSED'){throw};return $false}
}
@{
 legacy_ok=(Accepted 134217728 134217728 $false 0)
 legacy_large=(Accepted 366682664 366682664 $false 366682664)
 module_ok=(Accepted 366682664 366682664 $true 366682664)
 module_wrong_size=(Accepted 366682663 366682663 $true 366682664)
 module_missing_approval=(Accepted 366682664 366682664 $true 0)
 module_oversize=(Accepted 536870913 536870913 $true 536870913)
 changed_stat=(Accepted 366682664 366682665 $true 366682664)
 empty=(Accepted 0 0 $false 0)
}|ConvertTo-Json -Compress
'''.replace('__BOOTSTRAP__', str(HERE / 'bootstrap-runtime.ps1').replace("'", "''"))
        result = subprocess.run([shutil.which('pwsh'), '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {name: name in ('legacy_ok', 'module_ok') for name in
            ('legacy_ok', 'legacy_large', 'module_ok', 'module_wrong_size', 'module_missing_approval',
             'module_oversize', 'changed_stat', 'empty')})

    def test_retained_owner_bindings_bypass_only_durable_binding_reads_not_birth_checks(self):
        self.assertIn("if(-not $PSBoundParameters.ContainsKey('OwnedBindingsBase64'))", CLEANUP)
        self.assertIn("$OwnedBindingsBase64.Length -gt 4096", CLEANUP)
        self.assertIn("$property.Name -notin @('runtime','relay')", CLEANUP)
        self.assertIn("$p.StartTime.ToUniversalTime().Ticks -eq $owned.start_ticks", CLEANUP)
        self.assertIn("@('stop',$context.container_id)", CLEANUP)
        self.assertIn("$context.owns_container -ne $true", CLEANUP)

    def test_legacy_defaults_and_fixed_name_remain(self):
        self.assertIn("[string]$GpuProfile='ui_smoke'", BOOTSTRAP)
        self.assertIn("[ValidateSet('legacy','makepad_remote71')][string]$RuntimeProfile='legacy'", BOOTSTRAP)
        self.assertIn("../../reports/evidence/ai-execution-workspace-2026-10-08", BOOTSTRAP)
        self.assertIn("source_revision='105158e08c89d47f57af4621420ed68eb3a147ce'", BOOTSTRAP)
        self.assertIn("$selectedContainer='aiui-workspace-20261008'", UPLOAD)
        self.assertNotIn("[string]$ContainerName", BOOTSTRAP)

    def test_remote_owner_is_required_bounded_and_not_a_legacy_override(self):
        for guard in (
            "[string]::IsNullOrWhiteSpace($Owner)",
            "[Text.Encoding]::UTF8.GetByteCount($Owner) -gt 128",
            "$Owner -match '[\\x00-\\x1f\\x7f]'",
            "REMOTE_OWNER_REQUIRED_BOUNDED",
            "OWNER_REQUIRES_REMOTE_PROFILE",
        ):
            self.assertIn(guard, BOOTSTRAP)
        self.assertLess(BOOTSTRAP.index("REMOTE_OWNER_REQUIRED_BOUNDED"), BOOTSTRAP.index("Invoke-WorkspaceGpuPolicy"))

    def test_remote_requires_trusted_gpu_without_changing_legacy_default(self):
        self.assertIn("$PSBoundParameters.ContainsKey('GpuProfile') -and $GpuProfile -ne 'gpu_nvidia_test'", BOOTSTRAP)
        self.assertIn("throw 'REMOTE_REQUIRED_GPU_PROFILE'", BOOTSTRAP)
        self.assertIn("$GpuProfile='gpu_nvidia_test'", BOOTSTRAP)
        self.assertIn("-Purpose runtime -OutputDirectory $out", BOOTSTRAP)
        self.assertIn("$admission.status -ne 'ADMITTED'", BOOTSTRAP)
        self.assertNotIn("waiver.json", BOOTSTRAP)

    def test_remote_fixed_host_elf_and_source_image_pins_have_no_source_parameter(self):
        for pin in (PIN, IMAGE, ELF):
            self.assertIn(pin, BOOTSTRAP)
        self.assertIn("../../reports/evidence/makepad-dev-integration-pilot-20261015/runtime-ram-waiver-1/linux-makepad-example-text-input", BOOTSTRAP)
        parameters = BOOTSTRAP.split("$ErrorActionPreference", 1)[0]
        for arbitrary in ("Source", "Executable", "Image", "Environment", "ContainerName"):
            self.assertNotRegex(parameters, rf"\${arbitrary}\b")

    def test_remote_creator_argv_is_exact_and_legacy_image_tag_remains(self):
        arrays = re.findall(r"\$runArgs=@\(([^\n]+)\)", BOOTSTRAP)
        self.assertEqual(len(arrays), 2)
        prefix = "'run','--detach','--rm','--name','aiui-workspace-20261008','--memory','1G','--cpus','1','--gpus','all',"
        self.assertEqual(arrays[0], prefix + "'--label',('aiui.toolkit.owner='+$Owner),'--label',('aiui.toolkit.nonce='+$nonce),$expectedImage,'sleep','1800'")
        self.assertEqual(arrays[1], prefix + "'aiui-makepad-runtime:20261006','sleep','1800'")
        self.assertIn("$nonce=[Guid]::NewGuid().ToString('N')", BOOTSTRAP)
        self.assertIn("-Label container-start -Executable $wslc -TimeoutSeconds 60 -OutputDirectory $out -CommandArgs $runArgs", BOOTSTRAP)

    def test_foreign_names_are_only_allowed_in_remote_branch_without_adoption(self):
        self.assertIn("if($remoteProfile){\n if($LASTEXITCODE -ne 0 -or @($inventory).Count -lt 1)", BOOTSTRAP)
        self.assertIn("(?m)(?:^|\\s)aiui-workspace-20261008(?:\\s|$)", BOOTSTRAP)
        self.assertIn("FIXED_CONTAINER_NAME_CONFLICT", BOOTSTRAP)
        self.assertIn("}elseif($LASTEXITCODE -ne 0 -or @($inventory).Count -ne 1)", BOOTSTRAP)
        self.assertIn("Existing WSLC session requires explicit trusted default-session connection", BOOTSTRAP)
        self.assertNotIn("owns_vm=$true", BOOTSTRAP)

    def test_remote_stage_is_bounded_exclusive_and_checks_hash_before_and_after(self):
        self.assertIn("$fixtureStream.Length -gt 128MB", BOOTSTRAP)
        self.assertIn("$beforeHash -cne $approvedFixtureSha256", BOOTSTRAP)
        self.assertIn("$afterHash -cne $approvedFixtureSha256", BOOTSTRAP)
        self.assertIn("$stagedHash -cne $approvedFixtureSha256", BOOTSTRAP)
        self.assertEqual(BOOTSTRAP.count("$hasher.ComputeHash($fixtureStream)"), 2)
        self.assertIn("$fixtureStream.CopyTo($destination,65536)", BOOTSTRAP)
        self.assertIn("$before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks", BOOTSTRAP)
        self.assertIn("[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None", BOOTSTRAP)

    def test_verified_native_incarnation_is_saved_before_any_upload(self):
        inspect = BOOTSTRAP.index("-CommandArgs @('inspect',$id)")
        created = BOOTSTRAP.index("$createdId=Get-RemoteCreatedContainerId -Creator $launch -Executable $wslc -ExpectedArgs $runArgs")
        owned = BOOTSTRAP.index("$ownedId=$id")
        context = BOOTSTRAP.index("Write-BootstrapJson 'context.json' $context")
        upload = BOOTSTRAP.index("& (Join-Path $PSScriptRoot 'upload-artifact.ps1')")
        self.assertLess(BOOTSTRAP.index("-Label container-start -Executable $wslc"), created)
        self.assertLess(created, inspect)
        self.assertLess(inspect, owned)
        self.assertLess(BOOTSTRAP.index("REMOTE_CREATOR_LABEL_MISMATCH"), owned)
        self.assertLess(owned, context)
        self.assertLess(context, upload)
        for field in ("exclusive_owner=$Owner", "exclusive_nonce=$nonce", "container_created=$containerCreated", "container_started_at=$containerStartedAt", "resumable=$false", "owns_vm=$false", "owns_container=$true"):
            self.assertIn(field, BOOTSTRAP)
        self.assertIn("$context.source_revision=$remoteSourceRevision", BOOTSTRAP)
        self.assertIn("GetProperty('Created').GetString()", BOOTSTRAP)
        self.assertIn("GetProperty('State').GetProperty('StartedAt').GetString()", BOOTSTRAP)
        self.assertIn("[IO.FileMode]::CreateNew", BOOTSTRAP)

    def test_remote_upload_is_fixture_only_and_exact_verified_cid(self):
        after_context = BOOTSTRAP.split("Write-BootstrapJson 'context.json' $context", 1)[1]
        # Include both approved fixture branches; stop the focus branch below.
        remote_upload = after_context.split(" if($remoteProfile){", 1)[1]
        default_upload, font_upload = remote_upload.split("  if($remoteProfile -and $RemoteFixture -in @('focus_trace71','module_shell71')){", 1)
        self.assertEqual(default_upload.count("-Artifact "), 2)
        self.assertIn("-Artifact fixture -OutputDirectory $out -ContainerId $ownedId", default_upload)
        self.assertIn("-Source $stagedFonts -Artifact launcher -OutputDirectory $out -ContainerId $ownedId", font_upload)
        self.assertIn("-ModuleShellBuildManifest $ModuleShellBuildManifest -ModuleShellBuildManifestSha256 $ModuleShellBuildManifestSha256 -ApprovedModuleShellElf $ApprovedModuleShellElf", font_upload)
        self.assertIn("}else{\n    & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source $stagedFonts -Artifact launcher -OutputDirectory $out -ContainerId $ownedId | Out-Null", font_upload)
        for role in ("input", "inventory", "launcher", "partial-stop"):
            self.assertIn(f"-Artifact {role} -OutputDirectory $out", after_context)

    def test_failure_retains_receipts_and_never_stops_by_name_or_vm(self):
        failure = BOOTSTRAP.split("}catch{\n $bootstrapError=$_", 1)[1]
        self.assertLess(failure.index("'bootstrap-failure.json'"), failure.index("@('stop',$stopId)"))
        self.assertIn("$stopId=$ownedId", failure)
        self.assertIn("if($remoteProfile -and -not $stopId){$stopId=$createdId}", failure)
        self.assertIn("if($stopId){", failure)
        self.assertIn("verified_owned_container_id=$ownedId", failure)
        self.assertIn("$failure.creator_proven_container_id=$createdId", failure)
        self.assertIn("$failure.inspect_approved=[bool]$ownedId", failure)
        self.assertIn("UNPROVEN_NO_STOP_AUTHORITY", failure)
        self.assertIn("cleanup_not_inferred=$true", failure)
        self.assertIn("throw $bootstrapError", failure)
        self.assertNotIn("@('stop','aiui-workspace-20261008')", BOOTSTRAP)
        self.assertNotRegex(BOOTSTRAP, r"@\('(?:terminate|shutdown)'|--shutdown")

    def test_uploader_explicit_cid_is_strict_conflict_checked_and_context_bound(self):
        self.assertIn("$PSBoundParameters.ContainsKey('ContainerId')", UPLOAD)
        self.assertIn("$ContainerId -cnotmatch '^[0-9a-f]{64}$'", UPLOAD)
        self.assertIn("if($Artifact -in @('ai-revit-app','ai-revit-client','ai-revit-resources')){throw 'CONTAINER_ARGUMENTS_CONFLICT'}", UPLOAD)
        self.assertIn("$PSBoundParameters.ContainsKey($registrationParameter)", UPLOAD)
        self.assertIn("$uploadContext.container_id -cne $ContainerId", UPLOAD)
        self.assertIn("$uploadContext.owns_vm -ne $false", UPLOAD)
        self.assertIn("EXCLUSIVE_UPLOAD_RECEIPT_EXISTS", UPLOAD)
        self.assertIn("@('exec','-i',$selectedContainer,'sh','-c'", UPLOAD)
        self.assertLess(UPLOAD.index("CONTAINER_ID_INVALID"), UPLOAD.index("$python=Join-Path"))

    def test_legacy_upload_aliases_and_registered_transfer_dispatch_remain(self):
        for role, target in {
            "fixture": "/opt/proof/ai-workspace-fixture",
            "input": "/opt/proof/ai-workspace-xinput",
            "inventory": "/opt/proof/aiui-xinput",
            "launcher": "/opt/proof/fixture-launch.sh",
            "'partial-stop'": "/opt/proof/partial-stop.sh",
        }.items():
            self.assertIn(f"{role}='{target}'", UPLOAD)
        self.assertIn("trusted_artifact_transfer.py') upload --registration $Registration --registration-sha256 $RegistrationSha256 --container-binding $ContainerBinding --container-binding-sha256 $ContainerBindingSha256 --artifact $Artifact --source $Source --output-dir $OutputDirectory", UPLOAD)
        self.assertIn("$record.container_id=$ContainerId", UPLOAD)
        self.assertIn("if($explicitContainerId){\n  $record.container_id", UPLOAD)
        self.assertIn("Write-UploadReceipt (Join-Path $OutputDirectory ($Artifact+'-upload.json'))", UPLOAD)
        self.assertIn("[IO.File]::Move($temporary,$Path)", UPLOAD)
        self.assertIn("$stream.Flush($true)", UPLOAD)


class BootstrapRemoteDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            raise RuntimeError("PowerShell is required for isolated bootstrap decision units")
        # Only AST-selected production code runs. The fixed creator argv is
        # evaluated from its own assignment, not copied into a second validator.
        decision_script = r"""
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__BOOTSTRAP__',[ref]$tokens,[ref]$parseErrors)
if(@($parseErrors).Count){throw 'Bootstrap parse failed'}
$functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-RemoteCreatedContainerId'},$true))
if($functions.Count -ne 1){throw 'Expected one actual creator guard'}
. ([scriptblock]::Create($functions[0].Extent.Text))
# Run actual parameter defaults/ValidateSet, the actual legacy guard, and the
# actual fixed selection switch. Never evaluate the staging/copy/bootstrap body.
$fixtureParams=@($ast.ParamBlock.Parameters|Where-Object {$_.Name.VariablePath.UserPath -in @('RuntimeProfile','RemoteFixture')})
$profileInit=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$remoteProfile'})
$fixtureInit=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$approvedFixtureSha256'})
$fixtureGuard=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('REMOTE_FIXTURE_REQUIRES_REMOTE_PROFILE')})
$fixtureSwitch=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.SwitchStatementAst] -and $node.Condition.Extent.Text -ceq '$RemoteFixture'},$true))
if($fixtureParams.Count -ne 2 -or $profileInit.Count -ne 1 -or $fixtureInit.Count -ne 1 -or $fixtureGuard.Count -ne 1 -or $fixtureSwitch.Count -ne 1){throw 'Expected actual fixture selection contract'}
$fixtureDecision=[scriptblock]::Create('param('+($fixtureParams.Extent.Text -join ',')+")`n"+
 $profileInit[0].Extent.Text+"`n"+$fixtureGuard[0].Extent.Text+"`n"+$fixtureInit[0].Extent.Text+
 "`nif(`$remoteProfile){`n`$script:fixtureSelectionReached=`$true`n"+$fixtureSwitch[0].Extent.Text+"`n}`n"+
 'return [ordered]@{choice=$RemoteFixture;remote=$remoteProfile;path=$approvedFixtureRelative;sha256=$approvedFixtureSha256}')
function Observe-FixtureChoice([hashtable]$Options){
 $script:fixtureSelectionReached=$false
 try{
  $selection=& $fixtureDecision @Options
  return [ordered]@{accepted=$true;selection_reached=$script:fixtureSelectionReached;selection=$selection}
 }catch{
  return [ordered]@{accepted=$false;selection_reached=$script:fixtureSelectionReached;
   error=$_.Exception.Message;error_id=$_.FullyQualifiedErrorId}
 }
}
$mainTry=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
if($mainTry.Count -ne 1 -or $mainTry[0].CatchClauses.Count -ne 1){throw 'Expected actual bootstrap failure catch'}
$catchText=$mainTry[0].CatchClauses[0].Body.Extent.Text
$failureCatch=[scriptblock]::Create($catchText.Substring(1,$catchText.Length-2))
$startupStatements=@($mainTry[0].Body.Statements)
$start=@($startupStatements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$launch'})
$end=@($startupStatements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$ownedId'})
if($start.Count -ne 1 -or $end.Count -ne 1){throw 'Expected actual creator-through-inspect approval slice'}
$startupApproval=[scriptblock]::Create($ast.Extent.Text.Substring($start[0].Extent.StartOffset,$end[0].Extent.EndOffset-$start[0].Extent.StartOffset))
$assignments=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$runArgs'},$true))
$Owner='unit-only-owner';$nonce='1'*32
$expectedImage='sha256:219e68c9b9ff3c0e24f8a2e937abe08beb98ebd2c88d551f25f09b052ff2107b'
$expectedArgs=@(& ([scriptblock]::Create($assignments[0].Right.Extent.Text)))
$wslc='C:\Program Files\WSL\wslc.exe'
$validCid='a'*64;$foreignCid='b'*64
function New-Creator {
 return ([pscustomobject]@{label='container-start';executable=$wslc;args=@($expectedArgs);
  exit_code=0;timed_out=$false;output_drained=$true;owned_tree_termination_requested=$false;
  stdout=($validCid+"`r`n")}|ConvertTo-Json -Depth 4|ConvertFrom-Json)
}
function Write-BootstrapJson([string]$Name,$Value){
 if($Name -cne 'bootstrap-failure.json'){throw 'Unexpected receipt write'}
 $script:failureRecord=$Value
}
function Observe-Failure($Creator,[bool]$Remote=$true,[string]$Approved='',[string]$Phase='inspect_failure'){
 $remoteProfile=$Remote;$ownedId=$null;$createdId=$null;$id=$null;$runArgs=$expectedArgs;$out='UNIT_ONLY_NO_FILES'
 $labels=@{'aiui.toolkit.owner'=$Owner;'aiui.toolkit.nonce'=$nonce}
 $metadataFixture=[pscustomobject]@{Id=$validCid;Name='/aiui-workspace-20261008';Image=$expectedImage;
  HostConfig=@{Memory=1073741824;NanoCpus=1000000000};State=@{Running=$true;StartedAt='2026-10-22T00:00:00.100000000Z'};
  Created='2026-10-22T00:00:00.000000000Z';Config=@{Labels=$labels};Labels=$labels}
 if($Phase -ceq 'labels_failure'){$metadataFixture.Config.Labels=$null}
 $inspectReceipt=[pscustomobject]@{exit_code=if($Approved -or $Phase -ceq 'labels_failure'){0}else{1};
  timed_out=$false;output_drained=$true;stdout=(ConvertTo-Json -InputObject @($metadataFixture) -Depth 8 -Compress)}
 function Get-Content([string]$Path,[switch]$Raw){
  switch([IO.Path]::GetFileName($Path)){
   'container-start.json' {return ($Creator|ConvertTo-Json -Depth 8 -Compress)}
   'container-inspect.json' {return ($inspectReceipt|ConvertTo-Json -Depth 8 -Compress)}
   default {throw 'Unexpected receipt read'}
  }
 }
 $script:stopCalls=[Collections.Generic.List[object]]::new();$script:inspectCalls=[Collections.Generic.List[object]]::new();$script:failureRecord=$null
 $capture={param($Label,$Executable,$TimeoutSeconds,$OutputDirectory,[string[]]$CommandArgs)
  if($Executable -cne $wslc -or $TimeoutSeconds -ne 30 -or $OutputDirectory -cne $out){throw 'Unexpected capture invocation'}
  switch -CaseSensitive ($Label){
   'container-inspect' {$script:inspectCalls.Add([object]$CommandArgs)}
   'failed-bootstrap-container-stop' {$script:stopCalls.Add([object]$CommandArgs)}
   default {throw 'Unexpected capture operation'}
  }
 }
 $preserved=$null;$original=$null
 try{try{. $startupApproval;throw 'CONTROLLED_LATER_FAILURE'}catch{$original=$_.Exception.Message;. $failureCatch}}catch{$preserved=$_.Exception.Message}
 return [ordered]@{created_id=$createdId;inspect_calls=@($script:inspectCalls.ToArray());stop_calls=@($script:stopCalls.ToArray());failure=$script:failureRecord;original_error=$original;preserved_error=$preserved}
}
$results=[ordered]@{}
$results['fixture_selection']=[ordered]@{
 default_remote=(Observe-FixtureChoice @{RuntimeProfile='makepad_remote71'})
 explicit_text=(Observe-FixtureChoice @{RuntimeProfile='makepad_remote71';RemoteFixture='text_input71'})
 focus=(Observe-FixtureChoice @{RuntimeProfile='makepad_remote71';RemoteFixture='focus_trace71'})
 focus_upper=(Observe-FixtureChoice @{RuntimeProfile='makepad_remote71';RemoteFixture='FOCUS_TRACE71'})
 default_legacy=(Observe-FixtureChoice @{})
 legacy_explicit_text=(Observe-FixtureChoice @{RemoteFixture='text_input71'})
 legacy_explicit_focus=(Observe-FixtureChoice @{RuntimeProfile='legacy';RemoteFixture='focus_trace71'})
 unknown_remote=(Observe-FixtureChoice @{RuntimeProfile='makepad_remote71';RemoteFixture='foreign'})
}
foreach($phase in @('inspect_failure','labels_failure')){$results[$phase]=Observe-Failure (New-Creator) $true '' $phase}
foreach($variant in @('failed','timed_out','undrained','forced','missing_status','string_exit','numeric_timeout','string_drained','wrong_executable','wrong_label','wrong_owner_arg','reordered_args','missing_arg','bad_cid','multiple_cids','uppercase_cid')){
 $creator=New-Creator;$creator.stdout=$foreignCid
 switch($variant){
  'failed' {$creator.exit_code=1}
  'timed_out' {$creator.timed_out=$true}
  'undrained' {$creator.output_drained=$false}
  'forced' {$creator.owned_tree_termination_requested=$true}
  'missing_status' {$creator.PSObject.Properties.Remove('output_drained')}
  'string_exit' {$creator.exit_code='0'}
  'numeric_timeout' {$creator.timed_out=0}
  'string_drained' {$creator.output_drained='true'}
  'wrong_executable' {$creator.executable='C:\foreign\wslc.exe'}
  'wrong_label' {$creator.label='foreign-start'}
  'wrong_owner_arg' {$i=[array]::IndexOf($expectedArgs,'--label')+1;$creator.args[$i]='aiui.toolkit.owner=foreign'}
  'reordered_args' {$creator.args[-1]='sleep';$creator.args[-2]='1800'}
  'missing_arg' {$creator.args=@($creator.args|Select-Object -Skip 1)}
  'bad_cid' {$creator.stdout='a'*63}
  'multiple_cids' {$creator.stdout=$validCid+"`n"+$foreignCid}
  'uppercase_cid' {$creator.stdout='C'*64}
 }
 $results[$variant]=Observe-Failure $creator
}
$results['remote_approved']=Observe-Failure (New-Creator) $true $validCid
$results['legacy_unapproved']=Observe-Failure (New-Creator) $false
$results['legacy_approved']=Observe-Failure (New-Creator) $false $validCid
$results|ConvertTo-Json -Depth 8 -Compress
""".replace("__BOOTSTRAP__", str((HERE / "bootstrap-runtime.ps1").resolve()).replace("'", "''"))
        completed = subprocess.run(
            [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", decision_script],
            capture_output=True, text=True, encoding="utf-8", timeout=20, check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(f"Isolated decision units failed: {completed.stderr}\n{completed.stdout}")
        cls.decisions = json.loads(completed.stdout)

    def test_actual_fixture_selection_default_and_focus_have_fixed_paths_and_hashes(self):
        choices = self.decisions["fixture_selection"]
        for name in ("default_remote", "explicit_text"):
            with self.subTest(choice=name):
                result = choices[name]
                self.assertTrue(result["accepted"])
                self.assertTrue(result["selection_reached"])
                self.assertEqual(result["selection"], {
                    "choice": "text_input71", "remote": True,
                    "path": "../../reports/evidence/makepad-dev-integration-pilot-20261015/runtime-ram-waiver-1/linux-makepad-example-text-input",
                    "sha256": ELF,
                })
        result = choices["focus"]
        self.assertTrue(result["accepted"])
        self.assertTrue(result["selection_reached"])
        self.assertEqual(result["selection"], {
            "choice": "focus_trace71", "remote": True,
            "path": "../../reports/evidence/makepad-dev-remote-api-adoption-v1/linux-focus-build-34/linux-toolkit-remote-focus-trace-fixture",
            "sha256": FOCUS_ELF,
        })
        upper = choices["focus_upper"]
        self.assertTrue(upper["accepted"])
        self.assertTrue(upper["selection_reached"])
        self.assertEqual(upper["selection"], {**result["selection"], "choice": "FOCUS_TRACE71"})

    def test_actual_fixture_legacy_conflict_and_unknown_choice_refuse_before_selection(self):
        choices = self.decisions["fixture_selection"]
        legacy = choices["default_legacy"]
        self.assertTrue(legacy["accepted"])
        self.assertFalse(legacy["selection_reached"])
        self.assertFalse(legacy["selection"]["remote"])
        self.assertEqual(legacy["selection"]["choice"], "text_input71")
        self.assertIsNone(legacy["selection"]["path"])
        for name in ("legacy_explicit_text", "legacy_explicit_focus"):
            with self.subTest(choice=name):
                result = choices[name]
                self.assertFalse(result["accepted"])
                self.assertFalse(result["selection_reached"])
                self.assertEqual(result["error"], "REMOTE_FIXTURE_REQUIRES_REMOTE_PROFILE")
        result = choices["unknown_remote"]
        self.assertFalse(result["accepted"])
        self.assertFalse(result["selection_reached"])
        self.assertIn("ParameterArgumentValidationError", result["error_id"])

    def assert_preserved_failure(self, result):
        self.assertTrue(result["original_error"])
        self.assertEqual(result["preserved_error"], result["original_error"])
        self.assertTrue(result["failure"]["cleanup_not_inferred"])
        self.assertFalse(result["failure"]["owns_vm"])

    def test_successful_creator_then_inspect_or_labels_failure_stops_only_created_cid(self):
        for phase in ("inspect_failure", "labels_failure"):
            with self.subTest(phase=phase):
                result = self.decisions[phase]
                self.assert_preserved_failure(result)
                self.assertEqual(result["original_error"], {
                    "inspect_failure": "Container inspection failed",
                    "labels_failure": "REMOTE_CREATOR_LABEL_MISMATCH",
                }[phase])
                self.assertEqual(result["created_id"], "a" * 64)
                self.assertEqual(result["inspect_calls"], [["inspect", "a" * 64]])
                self.assertEqual(result["stop_calls"], [["stop", "a" * 64]])
                self.assertIsNone(result["failure"]["verified_owned_container_id"])
                self.assertFalse(result["failure"]["inspect_approved"])
                self.assertEqual(result["failure"]["cleanup_stop_authority"], "SUCCESSFUL_FIXED_CREATOR")

    def assert_no_creator_stop(self, variants):
        for variant in variants:
            with self.subTest(variant=variant):
                result = self.decisions[variant]
                self.assert_preserved_failure(result)
                self.assertIsNone(result["created_id"])
                self.assertEqual(result["inspect_calls"], [])
                self.assertEqual(result["stop_calls"], [])
                self.assertIsNone(result["failure"]["cleanup_stop_container_id"])
                self.assertEqual(result["failure"]["cleanup_stop_authority"], "UNPROVEN_NO_STOP_AUTHORITY")

    def test_failed_timed_out_undrained_or_forced_run_stdout_never_authorizes_stop(self):
        self.assert_no_creator_stop(("failed", "timed_out", "undrained", "forced"))

    def test_receipt_type_or_fixed_command_drift_never_authorizes_stop(self):
        self.assert_no_creator_stop(("missing_status", "string_exit", "numeric_timeout", "string_drained",
                                    "wrong_executable", "wrong_label", "wrong_owner_arg", "reordered_args", "missing_arg"))

    def test_malformed_multiple_or_uppercase_creator_cids_never_authorize_stop(self):
        self.assert_no_creator_stop(("bad_cid", "multiple_cids", "uppercase_cid"))

    def test_inspect_approved_remote_keeps_existing_stop_authority(self):
        result = self.decisions["remote_approved"]
        self.assert_preserved_failure(result)
        self.assertEqual(result["stop_calls"], [["stop", "a" * 64]])
        self.assertTrue(result["failure"]["inspect_approved"])
        self.assertEqual(result["failure"]["cleanup_stop_authority"], "INSPECT_APPROVED")

    def test_legacy_still_requires_inspect_approval_not_creator_stdout(self):
        for variant, expected in (("legacy_unapproved", []), ("legacy_approved", [["stop", "a" * 64]])):
            with self.subTest(variant=variant):
                result = self.decisions[variant]
                self.assert_preserved_failure(result)
                self.assertEqual(result["stop_calls"], expected)
                self.assertNotIn("creator_proven_container_id", result["failure"])


class BootstrapFocusFontDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            raise RuntimeError("PowerShell is required for isolated font contract units")
        # Synthetic observations exercise actual pure guards, not a historical
        # manifest/file attestation. No artifact reads, copies or WSLC commands.
        script = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__BOOTSTRAP__',[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'Bootstrap parse failed'}
foreach($name in @('Get-RemoteFocusFontContract','Assert-RemoteFocusFontListing')){
 $found=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
 if($found.Count -ne 1){throw 'Expected actual pure font function'}
 . ([scriptblock]::Create($found[0].Extent.Text))
}
$uploadAst=[Management.Automation.Language.Parser]::ParseFile('__UPLOAD__',[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'Uploader parse failed'}
$uploadFunction=@($uploadAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-RemoteFontArchiveStage'},$true))
$roleGuards=@($uploadAst.FindAll({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and
 $node.Extent.Text.Contains('$moduleShellArgumentsSupplied -and $Artifact -notin')},$true))
if($uploadFunction.Count -ne 1 -or $roleGuards.Count -ne 1){throw 'Expected actual uploader font stage and role guards'}
. ([scriptblock]::Create($uploadFunction[0].Extent.Text))
$moduleRoleGuard=[scriptblock]::Create($roleGuards[0].Extent.Text)
$names=@('IBMPlexSans-Text.ttf','IBMPlexSans-SemiBold.ttf','IBMPlexSans-Italic.ttf','IBMPlexSans-BoldItalic.ttf',
 'LiberationMono-Regular.ttf','fa-solid-900.ttf','LXGWWenKaiRegular.ttf','LXGWWenKaiBold.ttf','NotoColorEmoji.ttf')
$target='/opt/makepad-operator/.cache/makepad-dev-pilot-20261015/source-71c9ddc/widgets/resources'
function New-SyntheticOptions {
 return @{Manifest=[pscustomobject]@{source_sha='71c9ddcbb9c01dd208f99621fdd71024a5d35c65';
   archive_sha256='394798AFC3B47F508A9D1A1DD7B50D1465B81BC2906A91F8F8A04AD5A3E30CEA';target_directory=$target;
   files=@(foreach($name in $names){[pscustomobject]@{name=$name;bytes=1;sha256=('A'*64);source='C:\foreign; ignored-source'}})};
  ManifestSha256='6288DAA9A209B6741D6AEE02387F0ABE201F02A223223C06A99395EE271F92B1';ManifestBytes=1000;
  ArchiveSha256='394798AFC3B47F508A9D1A1DD7B50D1465B81BC2906A91F8F8A04AD5A3E30CEA';ArchiveBytes=49539584}
}
function Observe-Contract([hashtable]$Options){
 try{return @{accepted=$true;contract=(Get-RemoteFocusFontContract @Options)}}
 catch{return @{accepted=$false;error=$_.Exception.Message}}
}
$options=New-SyntheticOptions
$contract=Get-RemoteFocusFontContract @options
$results=[ordered]@{valid=(Observe-Contract $options)}
foreach($variant in @('manifest_pin','archive_pin','manifest_bound','archive_bound','source_pin','manifest_archive',
 'target','missing_row','extra_row','foreign_name','traversal','order','duplicate','bad_sha','bool_bytes','negative_bytes','ignored_source')){
 $options=New-SyntheticOptions
 switch($variant){
  manifest_pin {$options.ManifestSha256='B'*64}
  archive_pin {$options.ArchiveSha256='B'*64}
  manifest_bound {$options.ManifestBytes=16385}
  archive_bound {$options.ArchiveBytes=49539583}
  source_pin {$options.Manifest.source_sha='0'*40}
  manifest_archive {$options.Manifest.archive_sha256='B'*64}
  target {$options.Manifest.target_directory='/foreign/resources'}
  missing_row {$options.Manifest.files=@($options.Manifest.files|Select-Object -First 8)}
  extra_row {$options.Manifest.files+=($options.Manifest.files[0])}
  foreign_name {$options.Manifest.files[0].name='foreign.ttf'}
  traversal {$options.Manifest.files[0].name='../IBMPlexSans-Text.ttf'}
  order {$swap=$options.Manifest.files[0];$options.Manifest.files[0]=$options.Manifest.files[1];$options.Manifest.files[1]=$swap}
  duplicate {$options.Manifest.files[1].name=$options.Manifest.files[0].name}
  bad_sha {$options.Manifest.files[0].sha256='bad'}
  bool_bytes {$options.Manifest.files[0].bytes=$true}
  negative_bytes {$options.Manifest.files[0].bytes=-1}
  ignored_source {$options.Manifest.files[0].source='$(MUST_NOT_EXECUTE)/../../foreign'}
 }
 $results[$variant]=Observe-Contract $options
}
$results.listings=[ordered]@{}
foreach($variant in @('lf','crlf','foreign','order','extra','truncated','banner','failed','timed_out','undrained','stderr','string_flag')){
 $receipt=[pscustomobject]@{exit_code=0;timed_out=$false;output_drained=$true;stdout=(($names -join "`n")+"`n");stderr=''}
 switch($variant){
  crlf {$receipt.stdout=($names -join "`r`n")+"`r`n"}
  foreign {$receipt.stdout=$receipt.stdout.Replace($names[0],'foreign.ttf')}
  order {$reordered=@($names);$reordered[0]=$names[1];$reordered[1]=$names[0];$receipt.stdout=($reordered -join "`n")+"`n"}
  extra {$receipt.stdout+="foreign.ttf`n"}
  truncated {$receipt.stdout=($names[0..7] -join "`n")+"`n"}
  banner {$receipt.stdout="banner`n"+$receipt.stdout}
  failed {$receipt.exit_code=1}
  timed_out {$receipt.timed_out=$true}
  undrained {$receipt.output_drained=$false}
  stderr {$receipt.stderr='warning'}
  string_flag {$receipt.output_drained='true'}
 }
 try{Assert-RemoteFocusFontListing $receipt $contract;$results.listings[$variant]=$true}
 catch{$results.listings[$variant]=$false}
}
$guards=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and
 $node.Clauses[0].Item1.Extent.Text -ceq "`$remoteProfile -and `$RemoteFixture -in @('focus_trace71','module_shell71')"},$true))
if($guards.Count -ne 2){throw 'Expected Focus and ModuleShell font stage/delivery guards'}
$results.guards=@(foreach($guard in $guards){
 $condition=[scriptblock]::Create($guard.Clauses[0].Item1.Extent.Text)
 foreach($case in @(@{remote=$true;choice='focus_trace71'},@{remote=$true;choice='FOCUS_TRACE71'},
  @{remote=$true;choice='Focus_Trace71'},@{remote=$true;choice='module_shell71'},
  @{remote=$true;choice='text_input71'},@{remote=$false;choice='module_shell71'})){
  $remoteProfile=$case.remote;$RemoteFixture=$case.choice
  [bool](& $condition)
 }
})
$fontSpecs=@(
 [pscustomobject]@{name='IBMPlexSans-Text.ttf';bytes=181792;sha256='8C358C56C56F76A28CECB8CA10734C1C9CAFA01A752DC8364B9EF7DE412437DC'},
 [pscustomobject]@{name='IBMPlexSans-SemiBold.ttf';bytes=182176;sha256='391BD290357CB19BACCCD66DC82F3213E0C66C34025A4DD3E15C49D3DB7C585E'},
 [pscustomobject]@{name='IBMPlexSans-Italic.ttf';bytes=184020;sha256='21EFFB0B8DABBBD6548DB1C581C68C6335F6FFAABD6946A6A73ADE24DEC050EB'},
 [pscustomobject]@{name='IBMPlexSans-BoldItalic.ttf';bytes=184656;sha256='451F1E35CF09EF4411C9F38E7EB7D4967AEF427C52E048DFF26CC36393937882'},
 [pscustomobject]@{name='LiberationMono-Regular.ttf';bytes=108168;sha256='3E396DDD3D1C7D3DCA1FB16DD64802B32F295F856AC10C0C1F2AB1C738196045'},
 [pscustomobject]@{name='fa-solid-900.ttf';bytes=426112;sha256='D2F0593540B0E33BA6DE255A54F272D466E31144806956BEA8CFDBF7EDFFC9BD'},
 [pscustomobject]@{name='LXGWWenKaiRegular.ttf';bytes=19073964;sha256='0819604AD9357AFBC6E7CC097328A16ED85143EE0848FFDA09FDA35A30DA6506'},
 [pscustomobject]@{name='LXGWWenKaiBold.ttf';bytes=18546748;sha256='7A356605EB36C92E29CC64090E2856E4675694572A2AE4DA84ADBADFFECAE907'},
 [pscustomobject]@{name='NotoColorEmoji.ttf';bytes=10643852;sha256='39EE3C587E10E89669B9FF32703261D10D5F9C4DD5AD147B6B5A1C5200591817'}
)
$archiveSha='394798AFC3B47F508A9D1A1DD7B50D1465B81BC2906A91F8F8A04AD5A3E30CEA'
$stagedPath=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'runtime-font-assets.tar'))
$foreignPath=[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'foreign.tar'))
$fontRows=@(foreach($font in $fontSpecs){[pscustomobject]@{name=$font.name;bytes=$font.bytes;sha256=$font.sha256}})
$stage=[pscustomobject]@{scope='ARTIFACT_COPY_NOT_RENDERING_PROOF';staged_archive=$stagedPath;
 contract=[pscustomobject]@{source_sha='71c9ddcbb9c01dd208f99621fdd71024a5d35c65';
  manifest_sha256='6288DAA9A209B6741D6AEE02387F0ABE201F02A223223C06A99395EE271F92B1';
  archive_sha256=$archiveSha;archive_bytes=49539584;target_directory=$target;files=$fontRows}}
function Observe-UploadFontStage($Value,[string]$Role,[string]$Path,[string]$Hash,[long]$Bytes,[bool]$ModuleShell){
 try{Assert-RemoteFontArchiveStage -Stage $Value -Artifact $Role -SourcePath $Path -ActualSha256 $Hash -ActualBytes $Bytes -ModuleShell $ModuleShell;return $true}
 catch{return $false}
}
$results.module_shell_stage=[ordered]@{
 valid=(Observe-UploadFontStage $stage 'launcher' $stagedPath $archiveSha 49539584 $true)
 wrong_hash=(Observe-UploadFontStage $stage 'launcher' $stagedPath ('A'*64) 49539584 $true)
 wrong_size=(Observe-UploadFontStage $stage 'launcher' $stagedPath $archiveSha 49539583 $true)
 wrong_path=(Observe-UploadFontStage $stage 'launcher' $foreignPath $archiveSha 49539584 $true)
 wrong_role=(Observe-UploadFontStage $stage 'fixture' $stagedPath $archiveSha 49539584 $true)
}
$legacyStage=[pscustomobject]@{staged_archive=$stagedPath;contract=[pscustomobject]@{archive_sha256=$archiveSha;archive_bytes=49539584}}
$results.legacy_font_stage=[ordered]@{
 valid=(Observe-UploadFontStage $legacyStage 'launcher' $stagedPath $archiveSha 49539584 $false)
 wrong_hash=(Observe-UploadFontStage $legacyStage 'launcher' $stagedPath ('A'*64) 49539584 $false)
 wrong_size=(Observe-UploadFontStage $legacyStage 'launcher' $stagedPath $archiveSha 49539583 $false)
 wrong_path=(Observe-UploadFontStage $legacyStage 'launcher' $foreignPath $archiveSha 49539584 $false)
}
$results.module_shell_roles=[ordered]@{}
foreach($role in @('fixture','launcher','input','inventory','partial-stop','ai-revit-app','ai-revit-client','ai-revit-resources')){
 $moduleShellArgumentsSupplied=$true;$Artifact=$role
 try{& $moduleRoleGuard;$results.module_shell_roles[$role]=$true}catch{$results.module_shell_roles[$role]=$false}
}
$results|ConvertTo-Json -Depth 10 -Compress
'''.replace("__BOOTSTRAP__", str(HERE / "bootstrap-runtime.ps1").replace("'", "''")) \
    .replace("__UPLOAD__", str(HERE / "upload-artifact.ps1").replace("'", "''"))
        completed = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", timeout=20, check=False)
        if completed.returncode != 0:
            raise AssertionError(f"Pure font decisions failed: {completed.stderr}\n{completed.stdout}")
        cls.decisions = json.loads(completed.stdout)

    def test_actual_font_contract_rejects_pin_bounds_source_and_allowlist_drift(self):
        self.assertTrue(self.decisions["valid"]["accepted"])
        for name, result in self.decisions.items():
            if name not in ("valid", "ignored_source", "listings", "guards", "module_shell_stage", "legacy_font_stage", "module_shell_roles"):
                with self.subTest(name=name): self.assertFalse(result["accepted"])
        contract = self.decisions["valid"]["contract"]
        self.assertEqual(self.decisions["ignored_source"]["contract"], contract)
        self.assertEqual(len(contract["files"]), 9)
        for row in contract["files"]:
            self.assertEqual(set(row), {"name", "bytes", "sha256"})

    def test_actual_font_listing_requires_exact_order_and_successful_drained_receipt(self):
        for name, accepted in self.decisions["listings"].items():
            with self.subTest(name=name): self.assertEqual(accepted, name in ("lf", "crlf"))

    def test_actual_font_stage_delivery_guards_and_fixed_upload_extract_order(self):
        self.assertEqual(self.decisions["guards"], [True, True, True, True, False, False] * 2)
        stage = BOOTSTRAP.index("$fontContract=Get-RemoteFocusFontContract")
        upload = BOOTSTRAP.index("-Source $stagedFonts -Artifact launcher")
        receipt_guard = BOOTSTRAP.index("throw 'REMOTE_FOCUS_FONT_UPLOAD_REFUSED'")
        listing = BOOTSTRAP.index("$fontListLabel=$fontEvidencePrefix+'-payload-list'")
        extraction = BOOTSTRAP.index("$fontExtractLabel=$fontEvidencePrefix+'-payload-extract'")
        self.assertLess(stage, upload)
        self.assertLess(upload, receipt_guard)
        self.assertLess(receipt_guard, listing)
        self.assertLess(listing, extraction)
        delivery = BOOTSTRAP[upload:BOOTSTRAP.index("Write-BootstrapJson ($fontEvidencePrefix+'s-verified.json')")]
        for guard in ("$fontUpload.container_id -cne $ownedId", "$fontUpload.sha256 -cne $fontContract.archive_sha256",
                      "$fontUpload.bytes -ne $fontContract.archive_bytes", "$fontUpload.target -cne '/opt/proof/fixture-launch.sh'"):
            self.assertIn(guard, delivery)
        self.assertIn("-ModuleShellBuildManifest $ModuleShellBuildManifest -ModuleShellBuildManifestSha256 $ModuleShellBuildManifestSha256 -ApprovedModuleShellElf $ApprovedModuleShellElf", delivery)
        self.assertIn("@('exec',$ownedId,'tar','-tf','/opt/proof/fixture-launch.sh')", delivery)
        self.assertIn("tar -xf /opt/proof/fixture-launch.sh -C /opt/makepad-operator/.cache/makepad-dev-pilot-20261015/source-71c9ddc/widgets/resources", delivery)
        self.assertIn("@('exec',$ownedId,'sha256sum',$fontTarget)", delivery)
        self.assertNotIn("$font.source", delivery)
        self.assertIn("$fontManifestSha=Get-RemoteAdmissionSha256 $fontManifestRaw", BOOTSTRAP)

    def test_actual_module_shell_font_upload_is_pinned_role_scoped_and_keeps_focus_legacy(self):
        self.assertEqual(self.decisions["module_shell_stage"], {
            "valid": True, "wrong_hash": False, "wrong_size": False, "wrong_path": False, "wrong_role": False
        })
        self.assertEqual(self.decisions["legacy_font_stage"], {
            "valid": True, "wrong_hash": False, "wrong_size": False, "wrong_path": False
        })
        self.assertEqual(self.decisions["module_shell_roles"], {
            "fixture": True, "launcher": True, "input": False, "inventory": False,
            "partial-stop": False, "ai-revit-app": False, "ai-revit-client": False, "ai-revit-resources": False
        })
        self.assertIn("$moduleShellArgumentsSupplied -and $Artifact -notin @('fixture','launcher')", UPLOAD)
        self.assertIn("Assert-RemoteFontArchiveStage -Stage $stageDocument.value", UPLOAD)
        self.assertIn("$expectedMemory=if($multiModule){2147483648}else{1073741824}", UPLOAD)
        self.assertIn("'--memory','1G','--cpus','1'", BOOTSTRAP)
        transfer = UPLOAD[UPLOAD.index("if($multiModuleProfile -and $Artifact -eq 'fixture'){", UPLOAD.index("$target=$targets[$Artifact]")):UPLOAD.index("$start=[Diagnostics.ProcessStartInfo]")]
        fixture_home, launcher_home = transfer.split("}elseif($multiModuleProfile -and $Artifact -eq 'launcher'){")
        self.assertIn("mkdir -m 700", fixture_home)
        self.assertIn("stat -c %a", launcher_home)
        self.assertNotIn("mkdir", launcher_home)


class BootstrapAdmissionDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            raise RuntimeError("PowerShell is required for isolated admission units")
        # Only actual pure functions and parameter/early-guard AST run here.
        # No ignored grant file, preflight, file writer, inventory or WSLC call.
        script = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__BOOTSTRAP__',[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'Bootstrap parse failed'}
foreach($name in @('Test-RemoteResourceAuthorizationScope','Assert-RemoteAdmissionJsonUnique','Get-RemoteAdmissionSha256','New-RemoteScopedRuntimeAdmission')){
 $found=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
 if($found.Count -ne 1){throw 'Expected actual pure admission function'}
 . ([scriptblock]::Create($found[0].Extent.Text))
}
$parameters=@($ast.ParamBlock.Parameters|Where-Object {$_.Name.VariablePath.UserPath -in @('RuntimeProfile','Owner','ResourceAuthorization')})
$init=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$remoteProfile'})
$guard=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.IfStatementAst] -and $_.Extent.Text.Contains('RESOURCE_AUTHORIZATION_REQUIRES_REMOTE_PROFILE')})
if($parameters.Count -ne 3 -or $init.Count -ne 1 -or $guard.Count -ne 1){throw 'Expected actual resource parameter/guard'}
$scope=[scriptblock]::Create('param('+($parameters.Extent.Text -join ',')+")`n"+$init[0].Extent.Text+"`n"+$guard[0].Extent.Text+
 "`nreturn (Test-RemoteResourceAuthorizationScope `$RuntimeProfile `$Owner `$ResourceAuthorization)")
$encoding=[Text.UTF8Encoding]::new($false,$true)
$grant=ConvertFrom-Json '__AUTHORIZATION_JSON__'
$at=[DateTimeOffset]::Parse('2026-10-22T09:00:00Z')
$stock=@{utc='2026-10-22T09:00:00Z';purpose='runtime';status='BLOCKED_ENVIRONMENT';
 active_rust_compilers=@();free_physical_kib=1531528;required_free_kib=2097152}
$raw=$stock|ConvertTo-Json -Compress
$options=@{RuntimeProfile='makepad_remote71';Owner='Makepad_Toolkit:remote-api-adoption-v1';ResourceAuthorization='remote_api_adoption_v1'}
function Observe([hashtable]$Options,[string]$Raw,[string]$Grant,[DateTimeOffset]$Now){
 try{
  $selected=& $scope @Options
  if(-not $selected){return @{accepted=$true;selected=$false}}
  $value=New-RemoteScopedRuntimeAdmission -StockBytes $encoding.GetBytes($Raw) -AuthorizationBytes $encoding.GetBytes($Grant) `
   -Profile $Options.RuntimeProfile -ResourceOwner $Options.Owner -Key $Options.ResourceAuthorization -Now $Now
  return @{accepted=$true;selected=$true;envelope=$value}
 }catch{return @{accepted=$false;error=$_.Exception.Message}}
}
$results=[ordered]@{low=(Observe $options $raw $grant $at);default=(Observe @{} $raw $grant $at)}
$high=$stock.Clone();$high.status='ADMITTED';$high.free_physical_kib=2097152
$results.high=Observe $options ($high|ConvertTo-Json -Compress) $grant $at
$stockGuards=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text -ceq '$useScopedAdmission' -and $n.Extent.Text.Contains('no WSLC runtime admission')},$true))
if($stockGuards.Count -ne 1){throw 'Expected actual stock admission guard'}
$stockGate=[scriptblock]::Create($stockGuards[0].Extent.Text)
$results.stock_boundaries=[ordered]@{}
foreach($name in @('below','exact')){
 $observed=$stock.Clone()
 if($name -eq 'below'){$observed.free_physical_kib=2097151;$observed.status='BLOCKED_ENVIRONMENT'}
 else{$observed.free_physical_kib=2097152;$observed.status='ADMITTED'}
 try{
  & {param($ObservedStock) $useScopedAdmission=$false;$admission=[pscustomobject]$ObservedStock;& $stockGate} $observed
  $results.stock_boundaries[$name]=@{accepted=$true;stock=$observed}
 }catch{$results.stock_boundaries[$name]=@{accepted=$false;stock=$observed;error=$_.Exception.Message}}
}
$inconsistent=$stock.Clone();$inconsistent.free_physical_kib=2097151;$inconsistent.status='ADMITTED'
$results.below_claims_admitted=Observe $options ($inconsistent|ConvertTo-Json -Compress) $grant $at
$inconsistent=$high.Clone();$inconsistent.status='BLOCKED_ENVIRONMENT'
$results.exact_claims_blocked=Observe $options ($inconsistent|ConvertTo-Json -Compress) $grant $at
$badOptions=@{
 legacy=@{ResourceAuthorization='remote_api_adoption_v1'};
 foreign=@{RuntimeProfile='makepad_remote71';Owner='foreign-owner';ResourceAuthorization='remote_api_adoption_v1'};
 badkey=@{RuntimeProfile='makepad_remote71';Owner=$options.Owner;ResourceAuthorization='foreign'}
}
foreach($key in $badOptions.Keys){$results[$key]=Observe $badOptions[$key] $raw $grant $at}
foreach($age in @(0,120000,120001,-1)){$results["age_$age"]=Observe $options $raw $grant $at.AddMilliseconds($age)}
$results.drift=Observe $options $raw ($grant+"`n") $at
$results.missing_grant=Observe $options $raw '' $at
$results.malformed=Observe $options '{' $grant $at
$results.duplicate=Observe $options '{"utc":1,"utc":2}' $grant $at
$variants=@{compiler=@(1);fake_admitted='ADMITTED';wrong_threshold=0;bool_memory=$true;wrong_purpose='warm-build';bad_utc='not-utc';waiver=$true}
foreach($name in $variants.Keys){
 $changed=$stock.Clone()
 switch($name){
  compiler {$changed.active_rust_compilers=$variants[$name]}
  fake_admitted {$changed.status=$variants[$name]}
  wrong_threshold {$changed.required_free_kib=$variants[$name]}
  bool_memory {$changed.free_physical_kib=$variants[$name]}
  wrong_purpose {$changed.purpose=$variants[$name]}
  bad_utc {$changed.utc=$variants[$name]}
  waiver {$changed.waiver=$variants[$name]}
 }
 $results[$name]=Observe $options ($changed|ConvertTo-Json -Compress) $grant $at
}
$results|ConvertTo-Json -Depth 12 -Compress
'''
        script = script.replace("__BOOTSTRAP__", str(HERE / "bootstrap-runtime.ps1").replace("'", "''"))
        script = script.replace("__AUTHORIZATION_JSON__", json.dumps(AUTHORIZATION_UTF8, ensure_ascii=True).replace("'", "''"))
        completed = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
        if completed.returncode != 0:
            raise AssertionError(f"Pure admission decision units failed: {completed.stderr}\n{completed.stdout}")
        cls.decisions = json.loads(completed.stdout)

    def test_actual_pinned_envelope_preserves_stock_bytes_status_and_default_control(self):
        result = self.decisions["low"]
        self.assertTrue(result["accepted"])
        envelope = result["envelope"]
        self.assertEqual(set(envelope), {"schema", "stock", "authorization"})
        self.assertEqual(envelope["schema"], "toolkit-remote-scoped-runtime-admission-v1")
        self.assertEqual(envelope["stock"]["path"], "runtime-admission.json")
        self.assertEqual(json.loads(envelope["stock"]["raw_utf8"])["status"], "BLOCKED_ENVIRONMENT")
        self.assertEqual(json.loads(envelope["stock"]["raw_utf8"])["free_physical_kib"], 1531528)
        self.assertEqual(envelope["authorization"]["raw_utf8"], AUTHORIZATION_UTF8)
        self.assertEqual(envelope["authorization"]["sha256"], "1D9BD6C43D7EBFDF550CE99BE7D6E9C4A0A0C1D7951D25F0B3331F548B6F1546")
        self.assertTrue(self.decisions["high"]["accepted"])
        self.assertEqual(self.decisions["default"], {"accepted": True, "selected": False})

    def test_actual_stock_runtime_two_gib_boundary_and_scoped_status_consistency(self):
        below = self.decisions["stock_boundaries"]["below"]
        exact = self.decisions["stock_boundaries"]["exact"]
        self.assertFalse(below["accepted"])
        self.assertEqual(below["stock"]["free_physical_kib"], 2097151)
        self.assertIn("no WSLC runtime admission", below["error"])
        self.assertTrue(exact["accepted"])
        self.assertEqual(exact["stock"]["free_physical_kib"], 2097152)
        self.assertEqual(exact["stock"]["required_free_kib"], 2097152)
        self.assertEqual(exact["stock"]["status"], "ADMITTED")
        self.assertFalse(self.decisions["below_claims_admitted"]["accepted"])
        self.assertFalse(self.decisions["exact_claims_blocked"]["accepted"])
        self.assertEqual(json.loads(self.decisions["high"]["envelope"]["stock"]["raw_utf8"])["status"], "ADMITTED")

    def test_actual_resource_key_legacy_and_foreign_owner_refuse(self):
        for name in ("legacy", "foreign", "badkey", "drift", "missing_grant"):
            with self.subTest(name=name): self.assertFalse(self.decisions[name]["accepted"])

    def test_actual_resource_exception_never_resets_original_stock_deadline(self):
        for age, accepted in ((0, True), (120000, True), (120001, False), (-1, False)):
            self.assertEqual(self.decisions[f"age_{age}"]["accepted"], accepted)

    def test_actual_resource_exception_rejects_malformed_compiler_and_fake_stock_status(self):
        for name in ("malformed", "duplicate", "compiler", "fake_admitted", "wrong_threshold", "bool_memory", "wrong_purpose", "bad_utc", "waiver"):
            with self.subTest(name=name): self.assertFalse(self.decisions[name]["accepted"])
        self.assertIn("elseif($admission.status -ne 'ADMITTED')", BOOTSTRAP)
        self.assertLess(BOOTSTRAP.index("$useScopedAdmission=Test-RemoteResourceAuthorizationScope"),
            BOOTSTRAP.index("Invoke-WorkspaceGpuPolicy"))
        self.assertIn("Write-BootstrapJson 'scoped-runtime-admission.json'", BOOTSTRAP)


class UploadProvenanceDecisions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            raise RuntimeError("PowerShell is required for isolated uploader decision units")
        script = r'''
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__UPLOAD__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Uploader parse failed'}
# No top-level upload, Add-Type, file/native inspection or WSLC is evaluated.
foreach($name in @('Convert-UploadJson','Assert-UploadContainer','Assert-UploadFdStable')){
 $f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
 if($f.Count -ne 1){throw 'Expected actual uploader decision function'}
 . ([scriptblock]::Create($f[0].Extent.Text))
}
$results=[ordered]@{}
$created=[DateTimeOffset]::UtcNow.AddSeconds(-2).ToString('yyyy-MM-ddTHH:mm:ss.fffffff')+'00Z'
$cid='a'*64;$image='sha256:'+'219e68c9b9ff3c0e24f8a2e937abe08beb98ebd2c88d551f25f09b052ff2107b'
$ctx=@{container_id=$cid;image=$image;container_name='aiui-workspace-20261008';owns_container=$true;owns_vm=$false;resumable=$false;runtime_profile='makepad_remote71';memory_max=1073741824;
 source_revision='71c9ddcbb9c01dd208f99621fdd71024a5d35c65';exclusive_owner='unit-owner';exclusive_nonce='1'*32;container_created=$created;container_started_at=$created}
$creator=@{executable='C:\Program Files\WSL\wslc.exe';exit_code=0;timed_out=$false;output_drained=$true;stdout=$cid;
 started_utc=$created;duration_ms=1;args=@('run','--detach','--rm','--name','aiui-workspace-20261008','--memory','1G','--cpus','1','--gpus','all',
 '--label','aiui.toolkit.owner=unit-owner','--label',('aiui.toolkit.nonce='+('1'*32)),$image,'sleep','1800')}
$actual=@{Id=$cid;Image=$image;Name='/aiui-workspace-20261008';Created=$created;State=@{Running=$true;StartedAt=$created};
 HostConfig=@{Memory=1073741824;NanoCpus=1000000000;Privileged=$false;NetworkMode='bridge'};Mounts=@();Ports=@{};
 Config=@{Cmd=@('sleep','1800');Entrypoint=$null;Labels=@{'aiui.toolkit.owner'='unit-owner';'aiui.toolkit.nonce'=('1'*32)}}}
function Inspect-Unit($value){
 return @{executable='C:\Program Files\WSL\wslc.exe';args=@('inspect',$cid);exit_code=0;timed_out=$false;output_drained=$true;stderr='';
  stdout=ConvertTo-Json -InputObject @($value) -Depth 12 -Compress}
}
function Observe-Unit($context,$creation,$inspection){
 try{return @{accepted=$true;container=(Assert-UploadContainer $context $creation $inspection $cid)}}
 catch{return @{accepted=$false;error=$_.Exception.Message}}
}
$results.valid=Observe-Unit $ctx $creator (Inspect-Unit $actual)
# Real WSLC inspect omits the default-false Privileged member. Authority for
# that default is the already verified exact creator argv (no --privileged).
$omitted=$actual.Clone();$omitted.HostConfig=$actual.HostConfig.Clone();$omitted.HostConfig.Remove('Privileged')
$results.valid_omitted_privileged=Observe-Unit $ctx $creator (Inspect-Unit $omitted)
foreach($priv in @($null,$true,0,'false')){
 $bad=$actual.Clone();$bad.HostConfig=$actual.HostConfig.Clone();$bad.HostConfig.Privileged=$priv
 $results['actual_privileged_'+[string]$priv]=Observe-Unit $ctx $creator (Inspect-Unit $bad)
}
foreach($field in @('container_id','image','exclusive_owner','exclusive_nonce','container_created','container_started_at','source_revision')){
 $bad=$ctx.Clone();$bad[$field]='foreign';$results['context_'+$field]=Observe-Unit $bad $creator (Inspect-Unit $actual)
}
foreach($field in @('exit_code','timed_out','output_drained','args','stdout','executable')){
 $bad=$creator.Clone();$bad[$field]=switch($field){exit_code {1} timed_out {$true} output_drained {$false} args {@('foreign')} default {'foreign'}}
 $results['creator_'+$field]=Observe-Unit $ctx $bad (Inspect-Unit $actual)
}
foreach($field in @('Id','Image','Created','Mounts')){
 $bad=$actual.Clone();$bad[$field]=if($field -eq 'Mounts'){@('foreign')}else{'foreign'}
 $results['actual_'+$field]=Observe-Unit $ctx $creator (Inspect-Unit $bad)
}
$fd=@{volume_serial='1';file_index='2';nlink='1';size='64';creation_time_100ns='3';last_write_time_100ns='4';change_time_100ns='5'}
try{Assert-UploadFdStable $fd $fd;$results.fd_valid=$true}catch{$results.fd_valid=$false}
foreach($field in @($fd.Keys)){
 $bad=$fd.Clone();$bad[$field]='99'
 try{Assert-UploadFdStable $fd $bad;$results['fd_'+$field]=$true}catch{$results['fd_'+$field]=$false}
}
foreach($name in @('hardlink','zero','empty')){
 $bad=$fd.Clone();if($name -eq 'hardlink'){$bad.nlink='2'}elseif($name -eq 'zero'){$bad.size='0'}else{$bad=@{}}
 try{Assert-UploadFdStable $bad $bad;$results['type_'+$name]=$true}catch{$results['type_'+$name]=$false}
}
$duplicate=[System.Text.Json.JsonDocument]::Parse('{"owner":"a","owner":"b"}')
try{[void](Convert-UploadJson $duplicate.RootElement);$results.duplicate_accepted=$true}catch{$results.duplicate_accepted=$false}finally{$duplicate.Dispose()}
$results|ConvertTo-Json -Depth 12 -Compress
'''.replace("__UPLOAD__", str(HERE / "upload-artifact.ps1").replace("'", "''"))
        proc = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=20)
        if proc.returncode:
            raise AssertionError(f"Isolated uploader decision test failed: {proc.stderr}")
        cls.decisions = json.loads(proc.stdout)

    def test_actual_container_incarnation_creator_and_labels_join(self):
        self.assertTrue(self.decisions["valid"]["accepted"], self.decisions["valid"])
        self.assertTrue(self.decisions["valid_omitted_privileged"]["accepted"], self.decisions["valid_omitted_privileged"])
        for key, value in self.decisions.items():
            if key.startswith(("context_", "creator_", "actual_")):
                with self.subTest(key=key): self.assertFalse(value["accepted"])

    def test_actual_fd_stats_fail_closed_and_duplicate_json_refused(self):
        self.assertTrue(self.decisions["fd_valid"])
        for key, value in self.decisions.items():
            if key.startswith(("fd_", "type_")) and key != "fd_valid":
                with self.subTest(key=key): self.assertFalse(value)
        self.assertFalse(self.decisions["duplicate_accepted"])

    def test_upload_uses_one_locked_source_handle_and_atomic_uuid_receipt(self):
        for fragment in ("toolkit-wslc-artifact-transfer-provenance-v1", "operation_id=$operationId",
            "[Guid]::NewGuid().ToString('D')", "Get-UploadFdStat $file", "$hasher.ComputeHash($file)",
            "source=@{path=$sourcePath;bytes_sent=$bytesSent;fd_before=$fdBefore;fd_after=$fdAfter",
            "sha256_before=$hashBefore;sha256_after=$hash", "stage_receipt=$stageDocument.ref",
            "creator_receipt=$creatorDocument.ref", "container_inspect_receipt=$inspectDocument.ref",
            "[IO.File]::Move($temporary,$Path)", "TRANSFER_ELF_MAGIC_REFUSED"):
            self.assertIn(fragment, UPLOAD)
        self.assertNotIn("Get-FileHash -LiteralPath $sourcePath", UPLOAD)
        self.assertIn("[IO.FileShare]::Read", UPLOAD)


if __name__ == "__main__":
    unittest.main()
