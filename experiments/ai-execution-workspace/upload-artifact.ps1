param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][ValidateSet('fixture','input','inventory','launcher','partial-stop','ai-revit-app','ai-revit-client','ai-revit-resources')][string]$Artifact,
 [Parameter(Mandatory=$true)][string]$OutputDirectory,
 [string]$Registration,[string]$RegistrationSha256,[string]$ContainerBinding,[string]$ContainerBindingSha256,[string]$ContainerId,
 [string]$ModuleShellBuildManifest,[string]$ModuleShellBuildManifestSha256,[string]$ApprovedModuleShellElf)
$ErrorActionPreference='Stop'
$moduleShellMakepadHome='/tmp/toolkit-module-shell-wslc-home'
$moduleShellProjectId='module-shell-wslc-v1'
$moduleShellLateProbe='1'
$moduleShellArgumentsSupplied=$PSBoundParameters.ContainsKey('ModuleShellBuildManifest') -or
 $PSBoundParameters.ContainsKey('ModuleShellBuildManifestSha256') -or $PSBoundParameters.ContainsKey('ApprovedModuleShellElf')
$multiModuleProfile=$false
$moduleShellApproval=$null
$moduleShellHostAdmissionDocument=$null
$moduleShellLaunchSettingsDocument=$null
if($moduleShellArgumentsSupplied -and $Artifact -notin @('fixture','launcher')){throw 'MODULE_SHELL_TRANSFER_FIXED_FIXTURE_ROLE_REQUIRED'}
if($moduleShellArgumentsSupplied -and -not $PSBoundParameters.ContainsKey('ContainerId')){throw 'MODULE_SHELL_TRANSFER_OWNED_CONTAINER_REQUIRED'}
if($moduleShellArgumentsSupplied -and ([string]::IsNullOrWhiteSpace($ModuleShellBuildManifest) -or
 [string]::IsNullOrWhiteSpace($ModuleShellBuildManifestSha256) -or [string]::IsNullOrWhiteSpace($ApprovedModuleShellElf))){
 throw 'MODULE_SHELL_OPERATOR_APPROVAL_ARGUMENTS_REQUIRED'
}
function Assert-UploadPath([string]$Path){
 $full=[IO.Path]::GetFullPath($Path)
 for($p=$full;$p;$p=[IO.Path]::GetDirectoryName($p)){
  $item=Get-Item -LiteralPath $p -Force
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'TRANSFER_REPARSE_REFUSED'}
 }
 return $full
}
function Get-UploadFdStat([IO.FileStream]$Stream){
 if(-not ('ToolkitUploadHandleV1' -as [type])){
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ToolkitUploadHandleV1 {
 [StructLayout(LayoutKind.Sequential)] struct Info {
  public uint attributes, creationLow, creationHigh, accessLow, accessHigh, writeLow, writeHigh;
  public uint volume, sizeHigh, sizeLow, links, indexHigh, indexLow;
 }
 [StructLayout(LayoutKind.Sequential)] struct Basic {
  public long creation, access, write, change; public uint attributes;
 }
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h, out Info info);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int kind, out Basic info, uint bytes);
 public static string[] Read(SafeFileHandle h) {
  Info i; Basic b;
  if(!GetFileInformationByHandle(h,out i) || !GetFileInformationByHandleEx(h,0,out b,(uint)Marshal.SizeOf<Basic>())) throw new Win32Exception();
  if((i.attributes & 0x410)!=0 || i.links!=1) throw new InvalidOperationException("TRANSFER_FILE_TYPE_REFUSED");
  return new[]{i.volume.ToString(CultureInfo.InvariantCulture),(((ulong)i.indexHigh<<32)|i.indexLow).ToString(CultureInfo.InvariantCulture),
   i.links.ToString(CultureInfo.InvariantCulture),(((ulong)i.sizeHigh<<32)|i.sizeLow).ToString(CultureInfo.InvariantCulture),
   b.creation.ToString(CultureInfo.InvariantCulture),b.write.ToString(CultureInfo.InvariantCulture),b.change.ToString(CultureInfo.InvariantCulture)};
 }
}
'@
 }
 $s=[ToolkitUploadHandleV1]::Read($Stream.SafeFileHandle)
 return [ordered]@{volume_serial=$s[0];file_index=$s[1];nlink=$s[2];size=$s[3];creation_time_100ns=$s[4];last_write_time_100ns=$s[5];change_time_100ns=$s[6]}
}
function Assert-UploadFdStable($Before,$After){
 $keys=@('volume_serial','file_index','nlink','size','creation_time_100ns','last_write_time_100ns','change_time_100ns')
 if($Before.Count -ne $keys.Count -or $After.Count -ne $keys.Count){throw 'TRANSFER_SOURCE_CHANGED'}
 foreach($k in $keys){if($Before[$k] -isnot [string] -or $After[$k] -isnot [string] -or $Before[$k] -cnotmatch '^[0-9]+$' -or $Before[$k] -cne $After[$k]){throw 'TRANSFER_SOURCE_CHANGED'}}
 if($Before.nlink -cne '1' -or [decimal]$Before.size -le 0 -or [decimal]$Before.size -gt 512MB -or [decimal]$Before.file_index -eq 0){throw 'TRANSFER_SOURCE_TYPE_REFUSED'}
}
function Assert-RemoteFontArchiveStage($Stage,[string]$Artifact,[string]$SourcePath,[string]$ActualSha256,[long]$ActualBytes,[bool]$ModuleShell){
 $pathMatches=$false
 try{$pathMatches=[IO.Path]::GetFullPath($Stage.staged_archive) -ieq [IO.Path]::GetFullPath($SourcePath)}catch{}
 if($Artifact -ne 'launcher'){throw 'MODULE_SHELL_FONT_ROLE_REFUSED'}
 if(-not $ModuleShell){
  if(-not $pathMatches -or $Stage.contract.archive_sha256 -cne $ActualSha256 -or $Stage.contract.archive_bytes -ne $ActualBytes){
   throw 'TRANSFER_STAGE_MISMATCH'
  }
  return
 }
 $contract=$Stage.contract
 $expectedFonts=@(
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
 $expectedArchiveSha256='394798AFC3B47F508A9D1A1DD7B50D1465B81BC2906A91F8F8A04AD5A3E30CEA'
 if(-not $pathMatches -or $Stage.scope -cne 'ARTIFACT_COPY_NOT_RENDERING_PROOF' -or
  $contract.source_sha -cne '71c9ddcbb9c01dd208f99621fdd71024a5d35c65' -or
  $contract.manifest_sha256 -cne '6288DAA9A209B6741D6AEE02387F0ABE201F02A223223C06A99395EE271F92B1' -or
  $contract.archive_sha256 -cne $expectedArchiveSha256 -or $ActualSha256 -cne $expectedArchiveSha256 -or
  -not ($contract.archive_bytes -is [int] -or $contract.archive_bytes -is [long]) -or
  $contract.archive_bytes -ne 49539584 -or $ActualBytes -ne $contract.archive_bytes -or
  $contract.target_directory -cne '/opt/makepad-operator/.cache/makepad-dev-pilot-20261015/source-71c9ddc/widgets/resources' -or
  $contract.files -isnot [array] -or $contract.files.Count -ne $expectedFonts.Count){
  throw 'MODULE_SHELL_FONT_ARCHIVE_APPROVAL_REFUSED'
 }
 for($i=0;$i -lt $expectedFonts.Count;$i++){
  $font=$contract.files[$i];$expected=$expectedFonts[$i]
  if($font.name -cne $expected.name -or
   -not ($font.bytes -is [int] -or $font.bytes -is [long]) -or $font.bytes -ne $expected.bytes -or
   $font.sha256 -isnot [string] -or $font.sha256 -cne $expected.sha256){throw 'MODULE_SHELL_FONT_ARCHIVE_ALLOWLIST_REFUSED'}
 }
}
function Convert-UploadJson($Node){
 switch($Node.ValueKind.ToString()){
  Object {$o=[ordered]@{};foreach($p in $Node.EnumerateObject()){if($o.Contains($p.Name)){throw 'TRANSFER_DUPLICATE_JSON'};$o[$p.Name]=Convert-UploadJson $p.Value};return ,$o}
  Array {$a=@(foreach($v in $Node.EnumerateArray()){Convert-UploadJson $v});return ,$a}
  String {return $Node.GetString()}
  Number {return $Node.GetInt64()}
  True {return $true}
  False {return $false}
  Null {return $null}
  default {throw 'TRANSFER_JSON_REFUSED'}
 }
}
function Read-UploadDocument([string]$Path){
 $p=Assert-UploadPath $Path
 $stream=[IO.FileStream]::new($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 $sha=[Security.Cryptography.SHA256]::Create()
 try{
  $before=Get-UploadFdStat $stream
  if($stream.Length -le 0 -or $stream.Length -gt 1MB){throw 'TRANSFER_DOCUMENT_BOUND'}
  $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes)
  Assert-UploadFdStable $before (Get-UploadFdStat $stream)
  $digest=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
  $raw=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
  $doc=[System.Text.Json.JsonDocument]::Parse($raw)
  try{$value=Convert-UploadJson $doc.RootElement}finally{$doc.Dispose()}
  $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
  if(-not $p.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'TRANSFER_DOCUMENT_OUTSIDE_PROJECT'}
  return @{value=$value;ref=@{path=[IO.Path]::GetRelativePath($root,$p).Replace('\','/');sha256=$digest}}
 }finally{$sha.Dispose();$stream.Dispose()}
}
function Assert-UploadContainer($Context,$Creator,$Inspection,[string]$Id){
 $image='sha256:219e68c9b9ff3c0e24f8a2e937abe08beb98ebd2c88d551f25f09b052ff2107b'
 $multiModule=$Context.wslc_profile -ceq 'wslc_multi_module'
 if($Context.Contains('wslc_profile') -and $Context.wslc_profile -cne 'wslc_multi_module' -and
  $Context.wslc_profile -cne 'wslc_single_app'){throw 'TRANSFER_PROFILE_REFUSED'}
 $expectedMemory=if($multiModule){2147483648}else{1073741824}
 foreach($key in @('owns_container','owns_vm','resumable')){if($Context[$key] -isnot [bool]){throw 'TRANSFER_CONTEXT_REFUSED'}}
 foreach($r in @($Creator,$Inspection)){foreach($key in @('timed_out','output_drained')){if($r[$key] -isnot [bool]){throw 'TRANSFER_RECEIPT_TYPES_REFUSED'}}}
 if($Context.container_id -cne $Id -or $Context.image -cne $image -or $Context.container_name -cne 'aiui-workspace-20261008' -or
  $Context.owns_container -ne $true -or $Context.owns_vm -ne $false -or $Context.resumable -ne $false -or
  $Context.source_revision -cne '71c9ddcbb9c01dd208f99621fdd71024a5d35c65' -or $Context.runtime_profile -cne 'makepad_remote71' -or
  $Context.exclusive_owner -isnot [string] -or [string]::IsNullOrWhiteSpace($Context.exclusive_owner) -or
  [Text.Encoding]::UTF8.GetByteCount($Context.exclusive_owner) -gt 128 -or $Context.exclusive_owner -match '[\x00-\x1f\x7f]' -or
  $Context.exclusive_nonce -cnotmatch '^[a-f0-9]{32}$'){throw 'TRANSFER_CONTEXT_REFUSED'}
 if($multiModule){
  $creatorArgs=@('run','--detach','--rm','--name','aiui-workspace-20261008','--memory','2G','--cpus','1','--gpus','all',
   '--env',('MAKEPAD_HOME='+$moduleShellMakepadHome),'--env',('TOOLKIT_MODULE_PROJECT_ID='+$moduleShellProjectId),
   '--env',('TOOLKIT_NATIVE_LATE_PROBE='+$moduleShellLateProbe),
   '--label',('aiui.toolkit.owner='+$Context.exclusive_owner),'--label',('aiui.toolkit.nonce='+$Context.exclusive_nonce),$image,'sleep','1800')
 }else{
  $creatorArgs=@('run','--detach','--rm','--name','aiui-workspace-20261008','--memory','1G','--cpus','1','--gpus','all',
   '--label',('aiui.toolkit.owner='+$Context.exclusive_owner),'--label',('aiui.toolkit.nonce='+$Context.exclusive_nonce),$image,'sleep','1800')
 }
 if($Creator.exit_code -isnot [long] -and $Creator.exit_code -isnot [int]){throw 'TRANSFER_CREATOR_REFUSED'}
 if($Creator.exit_code -ne 0 -or $Creator.timed_out -ne $false -or $Creator.output_drained -ne $true -or
  $Creator.executable -ine 'C:\Program Files\WSL\wslc.exe' -or $Creator.stdout.Trim() -cne $Id -or
  ($Creator.args|ConvertTo-Json -Compress) -cne ($creatorArgs|ConvertTo-Json -Compress)){throw 'TRANSFER_CREATOR_REFUSED'}
 if($Inspection.exit_code -isnot [long] -and $Inspection.exit_code -isnot [int]){throw 'TRANSFER_INSPECT_REFUSED'}
 if($Inspection.exit_code -ne 0 -or $Inspection.timed_out -ne $false -or $Inspection.output_drained -ne $true -or $Inspection.stderr -cne '' -or
  $Inspection.executable -ine 'C:\Program Files\WSL\wslc.exe' -or
  ($Inspection.args|ConvertTo-Json -Compress) -cne (@('inspect',$Id)|ConvertTo-Json -Compress)){throw 'TRANSFER_INSPECT_REFUSED'}
 $doc=[System.Text.Json.JsonDocument]::Parse([string]$Inspection.stdout)
 try{$actual=Convert-UploadJson $doc.RootElement}finally{$doc.Dispose()}
 if($actual -isnot [array] -or $actual.Count -ne 1){throw 'TRANSFER_INSPECT_REFUSED'}
 $a=$actual[0]
 # WSLC omits default-false Privileged. The exact creator argv above contains
 # no --privileged; an explicitly present value must still be boolean false.
 if($a.Id -cne $Id -or $a.Image -cne $image -or $a.Name -cne '/aiui-workspace-20261008' -or $a.State.Running -isnot [bool] -or $a.State.Running -ne $true -or
  $a.Created -cne $Context.container_created -or $a.State.StartedAt -cne $Context.container_started_at -or
   $a.HostConfig.Memory -ne $expectedMemory -or $Context.memory_max -ne $expectedMemory -or $a.HostConfig.NanoCpus -ne 1000000000 -or
  ($a.HostConfig.Contains('Privileged') -and ($a.HostConfig.Privileged -isnot [bool] -or $a.HostConfig.Privileged -ne $false)) -or
  $a.HostConfig.NetworkMode -cne 'bridge' -or @($a.Mounts).Count -ne 0 -or ($null -ne $a.Ports -and $a.Ports.Count -ne 0) -or
  $a.Config.Entrypoint -ne $null -or ($a.Config.Cmd|ConvertTo-Json -Compress) -cne (@('sleep','1800')|ConvertTo-Json -Compress) -or
  $a.Config.Labels.'aiui.toolkit.owner' -cne $Context.exclusive_owner -or $a.Config.Labels.'aiui.toolkit.nonce' -cne $Context.exclusive_nonce){throw 'TRANSFER_CONTAINER_CHANGED'}
 if($multiModule){
  if($Context.module_shell_makepad_home -cne $moduleShellMakepadHome -or
   $Context.module_shell_project_id -cne $moduleShellProjectId -or
   $Context.module_shell_native_late_probe -cne $moduleShellLateProbe -or $a.Config.Env -isnot [array]){
   throw 'MODULE_SHELL_CONTAINER_ENVIRONMENT_MISMATCH'
  }
  foreach($entry in @("MAKEPAD_HOME=$moduleShellMakepadHome","TOOLKIT_MODULE_PROJECT_ID=$moduleShellProjectId",
   "TOOLKIT_NATIVE_LATE_PROBE=$moduleShellLateProbe")){
   $key=$entry.Substring(0,$entry.IndexOf('=')+1)
   $matches=@($a.Config.Env|Where-Object {$_ -is [string] -and $_.StartsWith($key,[StringComparison]::Ordinal)})
   if($matches.Count -ne 1 -or $matches[0] -cne $entry){throw 'MODULE_SHELL_CONTAINER_ENVIRONMENT_MISMATCH'}
  }
 }
 $created=[DateTimeOffset]::Parse($a.Created);$started=[DateTimeOffset]::Parse($a.State.StartedAt);$dispatch=[DateTimeOffset]::Parse($Creator.started_utc)
 if($created -lt $dispatch.AddSeconds(-2) -or $created -gt $dispatch.AddMilliseconds($Creator.duration_ms).AddSeconds(5) -or
  $started -lt $created -or ($started-$created).TotalSeconds -gt 60 -or
  ([DateTimeOffset]::UtcNow-$created).TotalSeconds -lt 0 -or
  ([DateTimeOffset]::UtcNow-$created).TotalSeconds -gt 900){throw 'TRANSFER_CONTAINER_TIME_REFUSED'}
 return [ordered]@{container_id=$Id;image_id=$image;created=$a.Created;started_at=$a.State.StartedAt;owner=$Context.exclusive_owner;nonce=$Context.exclusive_nonce}
}
function Write-UploadReceipt([string]$Path,$Value,[string]$OperationId){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 24))
 $temporary=$Path+'.'+$OperationId+'.partial'
 $stream=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 # No overwrite: a failed publication retains its own partial evidence.
 [IO.File]::Move($temporary,$Path)
}
$selectedContainer='aiui-workspace-20261008'
$explicitContainerId=$PSBoundParameters.ContainsKey('ContainerId')
if($explicitContainerId){
 if($ContainerId -cnotmatch '^[0-9a-f]{64}$'){throw 'CONTAINER_ID_INVALID'}
 if($Artifact -in @('ai-revit-app','ai-revit-client','ai-revit-resources')){throw 'CONTAINER_ARGUMENTS_CONFLICT'}
 foreach($registrationParameter in @('Registration','RegistrationSha256','ContainerBinding','ContainerBindingSha256')){
  if($PSBoundParameters.ContainsKey($registrationParameter)){throw 'CONTAINER_ARGUMENTS_CONFLICT'}
 }
 $selectedContainer=$ContainerId
}
# Separate operator-only roles: never repoint the existing fixture alias. The
# registered transfer module uses the SAME WSLC exec stdio and OwnedDriver owner.
if($Artifact -in @('ai-revit-app','ai-revit-client','ai-revit-resources')){
 if(-not $Registration -or -not $RegistrationSha256 -or -not $ContainerBinding -or -not $ContainerBindingSha256){throw 'Pinned AI Revit registration and owned-container binding required'}
 $python=Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
 & $python -B (Join-Path $PSScriptRoot 'trusted_artifact_transfer.py') upload --registration $Registration --registration-sha256 $RegistrationSha256 --container-binding $ContainerBinding --container-binding-sha256 $ContainerBindingSha256 --artifact $Artifact --source $Source --output-dir $OutputDirectory
 if($LASTEXITCODE -ne 0){throw 'AI Revit fixed-role artifact transfer refused or failed'}
 return
}
if($explicitContainerId){
 $contextDocument=Read-UploadDocument (Join-Path $OutputDirectory 'context.json')
 $uploadContext=$contextDocument.value
 if($uploadContext.container_id -cne $ContainerId -or $uploadContext.container_name -cne 'aiui-workspace-20261008' -or $uploadContext.owns_container -ne $true -or $uploadContext.owns_vm -ne $false){throw 'OWNED_CONTAINER_ID_MISMATCH'}
 $multiModuleProfile=$uploadContext.wslc_profile -ceq 'wslc_multi_module'
 if($multiModuleProfile){
  if(-not $moduleShellArgumentsSupplied -or $uploadContext.runtime_profile -cne 'makepad_remote71' -or
   $uploadContext.module_shell_artifact_id -cne 'makepad-dev-app-module-shell-linux-71c9ddc' -or
   $uploadContext.module_instances -ne 2 -or
   $uploadContext.module_shell_profile_kind -cne 'ModuleShell' -or
   $uploadContext.module_shell_source_manifest_sha256 -cnotmatch '^[0-9A-F]{64}$' -or
   $uploadContext.module_shell_launch_settings_receipt -cne 'module-shell-launch-settings.json' -or
   $uploadContext.module_shell_launch_settings_sha256 -cnotmatch '^[0-9A-F]{64}$' -or
   $uploadContext.host_admission_receipt -cne 'module-shell-host-admission.json' -or
   $uploadContext.module_shell_artifact_path -isnot [string] -or $uploadContext.module_shell_artifact_sha256 -cnotmatch '^[0-9A-F]{64}$' -or
   $uploadContext.module_shell_preparation_sha256 -cnotmatch '^[0-9A-F]{64}$' -or
   $uploadContext.module_shell_native_build_receipt.path -cne 'reports/evidence/toolkit-makepad-dev-module-lifecycle-v1/wslc-hot-reload/linux-build05/native/module-shell-build.json' -or
   $uploadContext.module_shell_native_build_receipt.sha256 -cnotmatch '^[0-9A-F]{64}$' -or
   $uploadContext.module_shell_artifact_bytes -isnot [long] -and $uploadContext.module_shell_artifact_bytes -isnot [int]){
   throw 'MODULE_SHELL_CONTEXT_BINDING_REFUSED'
  }
  $python=Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
  $validator=Join-Path $PSScriptRoot 'module-shell-profile.py'
  if(-not (Test-Path -LiteralPath $python -PathType Leaf) -or -not (Test-Path -LiteralPath $validator -PathType Leaf)){
   throw 'MODULE_SHELL_PREPARATION_VALIDATOR_UNAVAILABLE'
  }
  $approvalRaw=& $python -I -B $validator validate-build-manifest --manifest $ModuleShellBuildManifest `
   --manifest-sha256 $ModuleShellBuildManifestSha256 --approved-elf $ApprovedModuleShellElf
  if($LASTEXITCODE -ne 0 -or -not $approvalRaw){throw 'MODULE_SHELL_BUILD_RECEIPT_NOT_APPROVED'}
  try{$moduleShellApproval=($approvalRaw -join "`n")|ConvertFrom-Json}catch{throw 'MODULE_SHELL_PREPARATION_OUTPUT_INVALID'}
  if($moduleShellApproval.schema -cne 'toolkit-makepad-dev-app-module-shell-wslc-preparation-v1' -or
   $moduleShellApproval.status -cne 'PREPARED_NOT_RUNTIME_ACCEPTANCE' -or
   $moduleShellApproval.profile.profile_id -cne 'wslc_multi_module' -or
   $moduleShellApproval.profile.profile_kind -cne 'ModuleShell' -or
   $moduleShellApproval.profile.module_shell.source_manifest_sha256 -cne $moduleShellApproval.source_manifest.sha256 -or
   $moduleShellApproval.profile.module_instances -ne 2 -or
   $moduleShellApproval.profile.container.memory_bytes -ne 2147483648 -or
   $moduleShellApproval.profile.container.cpus -ne 1 -or
   ($moduleShellApproval.profile.container.fixed_limit_args -join ',') -cne '--memory,2G,--cpus,1' -or
   $moduleShellApproval.profile.host_runtime_admission.minimum_free_bytes -ne 2684354560 -or
   $moduleShellApproval.profile.host_runtime_admission.host_ram_mode -cne 'USER_WAIVED' -or
   $moduleShellApproval.profile.host_runtime_admission.nested_increment_bytes -ne 0 -or
   $moduleShellApproval.build_receipt.path -cne $uploadContext.module_shell_build_receipt.path -or
   $moduleShellApproval.build_receipt.sha256 -cne $uploadContext.module_shell_build_receipt.sha256 -or
   $moduleShellApproval.native_build_receipt.path -cne $uploadContext.module_shell_native_build_receipt.path -or
   $moduleShellApproval.native_build_receipt.sha256 -cne $uploadContext.module_shell_native_build_receipt.sha256 -or
   $moduleShellApproval.source_manifest.path -cne $uploadContext.module_shell_source_manifest.path -or
   $moduleShellApproval.source_manifest.sha256 -cne $uploadContext.module_shell_source_manifest.sha256 -or
   $moduleShellApproval.artifact.path -cne $uploadContext.module_shell_artifact_path -or
   $moduleShellApproval.artifact.sha256 -cne $uploadContext.module_shell_artifact_sha256 -or
   $moduleShellApproval.artifact.bytes -ne $uploadContext.module_shell_artifact_bytes){
   throw 'MODULE_SHELL_CONTEXT_BINDING_MISMATCH'
  }
  if($moduleShellApproval.profile.module_shell.source_manifest_sha256 -cne $uploadContext.module_shell_source_manifest_sha256){
   throw 'MODULE_SHELL_SOURCE_PROFILE_BINDING_MISMATCH'
  }
  $moduleShellHostAdmissionDocument=Read-UploadDocument (Join-Path $OutputDirectory 'module-shell-host-admission.json')
  $hostAdmission=$moduleShellHostAdmissionDocument.value
  $admissionAge=[DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($hostAdmission.utc)
  if($hostAdmission.Count -ne 16 -or $hostAdmission.schema -cne 'toolkit-makepad-dev-app-module-shell-host-admission-v1' -or
   $hostAdmission.owner -cne $uploadContext.exclusive_owner -or
   $hostAdmission.source_manifest_sha256 -cne $moduleShellApproval.source_manifest.sha256 -or
   $admissionAge.TotalSeconds -lt 0 -or $admissionAge.TotalSeconds -gt 120 -or
   $hostAdmission.active_compiler_observation_performed -isnot [bool] -or $hostAdmission.active_compiler_observation_performed -ne $true -or
   $hostAdmission.active_rust_compilers -isnot [array] -or $hostAdmission.active_rust_compilers.Count -ne 0 -or
   $hostAdmission.host_ram_mode -cne 'USER_WAIVED' -or $hostAdmission.status -cne 'USER_WAIVED' -or
   $hostAdmission.available_memory_query_performed -isnot [bool] -or $hostAdmission.available_memory_query_performed -ne $false -or
   $hostAdmission.resource_admitted -isnot [bool] -or $hostAdmission.resource_admitted -ne $false -or
   $hostAdmission.minimum_free_bytes -ne 2684354560 -or $hostAdmission.minimum_free_kib -ne 2621440 -or
   $hostAdmission.container_memory_bytes -ne 2147483648 -or $hostAdmission.container_cpus -ne 1 -or
   $hostAdmission.nested_increment_kib -ne 0 -or $hostAdmission.scope -cne 'one_outer_runtime_admission' -or
   $hostAdmission.Contains('free_physical_kib') -or $hostAdmission.Contains('free_physical_bytes')){
   throw 'MODULE_SHELL_HOST_WAIVER_RECEIPT_REFUSED'
  }
  $moduleShellLaunchSettingsDocument=Read-UploadDocument (Join-Path $OutputDirectory 'module-shell-launch-settings.json')
  $launchSettings=$moduleShellLaunchSettingsDocument.value
  if($launchSettings.Count -ne 11 -or $moduleShellLaunchSettingsDocument.ref.sha256 -cne $uploadContext.module_shell_launch_settings_sha256 -or
   $launchSettings.schema -cne 'toolkit-makepad-dev-app-module-shell-launch-settings-v1' -or
   $launchSettings.status -cne 'PREPARED_NOT_RUNTIME_ACCEPTANCE' -or $launchSettings.profile_kind -cne 'ModuleShell' -or
   $launchSettings.makepad_home -cne $moduleShellMakepadHome -or $launchSettings.project_id -cne $moduleShellProjectId -or
   $launchSettings.native_late_probe -cne $moduleShellLateProbe -or $launchSettings.fresh_container_required -isnot [bool] -or
   $launchSettings.fresh_container_required -ne $true -or $launchSettings.home_scope -cne 'owned_container_local' -or
   $launchSettings.home_directory_mode -cne '0700' -or $launchSettings.late_probe_scope -cne 'one_shell_lifecycle' -or
   $launchSettings.public_ai_environment_used -isnot [bool] -or $launchSettings.public_ai_environment_used -ne $false -or
   $uploadContext.module_shell_makepad_home -cne $launchSettings.makepad_home -or
   $uploadContext.module_shell_project_id -cne $launchSettings.project_id -or
   $uploadContext.module_shell_native_late_probe -cne $launchSettings.native_late_probe){
   throw 'MODULE_SHELL_LAUNCH_SETTINGS_REFUSED'
  }
  $moduleShellPreparationDocument=Read-UploadDocument (Join-Path $OutputDirectory 'module-shell-build-approval.json')
  $prepared=$moduleShellPreparationDocument.value
  if($moduleShellPreparationDocument.ref.sha256 -cne $uploadContext.module_shell_preparation_sha256 -or
   $prepared.schema -cne $moduleShellApproval.schema -or $prepared.status -cne $moduleShellApproval.status -or
   $prepared.profile_id -cne $moduleShellApproval.profile_id -or
   $prepared.profile.container.memory_bytes -ne $moduleShellApproval.profile.container.memory_bytes -or
   $prepared.profile.container.cpus -ne $moduleShellApproval.profile.container.cpus -or
   $prepared.profile.profile_kind -cne 'ModuleShell' -or
   $prepared.profile.module_shell.source_manifest_sha256 -cne $moduleShellApproval.profile.module_shell.source_manifest_sha256 -or
   ($prepared.profile.container.fixed_limit_args -join ',') -cne ($moduleShellApproval.profile.container.fixed_limit_args -join ',') -or
   $prepared.profile.host_runtime_admission.minimum_free_bytes -ne $moduleShellApproval.profile.host_runtime_admission.minimum_free_bytes -or
   $prepared.profile.host_runtime_admission.host_ram_mode -cne 'USER_WAIVED' -or
   $prepared.build_receipt.sha256 -cne $moduleShellApproval.build_receipt.sha256 -or
   $prepared.native_build_receipt.sha256 -cne $moduleShellApproval.native_build_receipt.sha256 -or
   $prepared.source_manifest.sha256 -cne $moduleShellApproval.source_manifest.sha256 -or
   $prepared.artifact.sha256 -cne $moduleShellApproval.artifact.sha256 -or
   $prepared.artifact.bytes -ne $moduleShellApproval.artifact.bytes){throw 'MODULE_SHELL_PREPARATION_RECEIPT_MISMATCH'}
 }elseif($moduleShellArgumentsSupplied){throw 'MODULE_SHELL_CONTEXT_NOT_ENABLED'}
 if(Test-Path -LiteralPath (Join-Path $OutputDirectory ($Artifact+'-upload.json'))){throw 'EXCLUSIVE_UPLOAD_RECEIPT_EXISTS'}
}
$targets=@{fixture='/opt/proof/ai-workspace-fixture';input='/opt/proof/ai-workspace-xinput';inventory='/opt/proof/aiui-xinput';launcher='/opt/proof/fixture-launch.sh';'partial-stop'='/opt/proof/partial-stop.sh'}
$sourcePath=(Resolve-Path -LiteralPath $Source).Path
$sourcePath=Assert-UploadPath $sourcePath
$evidenceRoot=(Resolve-Path (Join-Path $PSScriptRoot '../../reports/evidence')).Path+'\'
if(-not $sourcePath.StartsWith($evidenceRoot,[StringComparison]::OrdinalIgnoreCase) -and -not ($Artifact -in @('launcher','partial-stop') -and $sourcePath -eq (Join-Path $PSScriptRoot ($(if($Artifact -eq 'launcher'){'fixture-launch.sh'}else{'partial-stop.sh'}))))){throw 'Only staged proof artifacts or the two fixed operator scripts can be uploaded'}
$info=Get-Item -LiteralPath $sourcePath
if($info.Length -le 0 -or $info.Length -gt 512MB){throw 'Bounded artifact size refused'}
# No transfer into a historical unbounded context. Fresh host reserve is
# separate from the per-container kernel quota and is checked before upload.
$storagePath=Join-Path $OutputDirectory 'storage/storage-admission.json'
if(-not (Test-Path -LiteralPath $storagePath -PathType Leaf)){throw 'STORAGE_QUOTA_UNSUPPORTED'}
$storage=Get-Content -LiteralPath $storagePath -Raw|ConvertFrom-Json
if($storage.schema -ceq 'toolkit-wslc-storage-admission-v1.1'){
 if($storage.storage_enforcement -cne 'monitored_soft_limit' -or $storage.hard_quota_enforced -ne $false -or
  $storage.decision.status -cne 'ADMITTED' -or $storage.capability.profile -cne 'focus_trace71' -or
  $storage.policy_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'storage-policy.json') -Algorithm SHA256).Hash){
  throw 'STORAGE_POLICY_INVALID'
 }
 $storagePython=Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
 & $storagePython -B (Join-Path $PSScriptRoot 'storage_policy.py') --admit-growth $OutputDirectory --incoming-bytes $info.Length | Out-Null
 if($LASTEXITCODE -ne 0){throw 'USAGE_NOT_VERIFIED'}
}elseif($storage.schema -cne 'toolkit-wslc-storage-admission-v1' -or
 $storage.decision.status -cne 'ADMITTED' -or $storage.capability.hard_limit_enforced -ne $true -or
 $storage.capability.limit_readback_bytes -ne 120000000000 -or
 $storage.capability.covers_all_writable_mounts -ne $true){throw 'STORAGE_QUOTA_UNSUPPORTED'}
$storageDrive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($sourcePath))
if($storageDrive.AvailableFreeSpace-$info.Length -lt 10000000000){throw 'HOST_STORAGE_RESERVE_REFUSED'}
$target=$targets[$Artifact]
$transferCommand='umask 077; dd bs=65536 of='+$target+' status=none && chmod 700 '+$target+' && sha256sum '+$target
if($multiModuleProfile -and $Artifact -eq 'fixture'){
 $homeModeCheck='[ "$(stat -c %a '+$moduleShellMakepadHome+')" = 700 ]'
 $transferCommand='umask 077; mkdir -m 700 '+$moduleShellMakepadHome+' && '+$homeModeCheck+
  ' && dd bs=65536 of='+$target+' status=none && chmod 700 '+$target+' && sha256sum '+$target
}elseif($multiModuleProfile -and $Artifact -eq 'launcher'){
 $homeModeCheck='[ "$(stat -c %a '+$moduleShellMakepadHome+')" = 700 ]'
 $transferCommand='umask 077; '+$homeModeCheck+
  ' && dd bs=65536 of='+$target+' status=none && chmod 700 '+$target+' && sha256sum '+$target
}
$start=[Diagnostics.ProcessStartInfo]::new('C:\Program Files\WSL\wslc.exe')
foreach($arg in @('exec','-i',$selectedContainer,'sh','-c',$transferCommand)){[void]$start.ArgumentList.Add($arg)}
$start.UseShellExecute=$false;$start.CreateNoWindow=$true
$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
$process=[Diagnostics.Process]::new();$process.StartInfo=$start
$file=[IO.FileStream]::new($sourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$hasher=[Security.Cryptography.SHA256]::Create()
$operationId=[Guid]::NewGuid().ToString('D')
$startedUtc=[DateTimeOffset]::UtcNow.ToString('o')
$remoteTransfer=$explicitContainerId -and $uploadContext.runtime_profile -ceq 'makepad_remote71' -and $Artifact -in @('fixture','launcher')
try{
 $fdBefore=Get-UploadFdStat $file
 Assert-UploadFdStable $fdBefore $fdBefore
 $hashBefore=[BitConverter]::ToString($hasher.ComputeHash($file)).Replace('-','');$file.Position=0
 if($explicitContainerId){
  if($Artifact -eq 'fixture'){
   $magic=[byte[]]::new(4);$file.ReadExactly($magic);$file.Position=0
   if([BitConverter]::ToString($magic) -cne '7F-45-4C-46'){throw 'TRANSFER_ELF_MAGIC_REFUSED'}
  }
  $creatorDocument=Read-UploadDocument (Join-Path $OutputDirectory 'container-start.json')
  $label=$Artifact+'-transfer-'+$operationId+'-inspect'
  & (Join-Path $PSScriptRoot 'capture-process.ps1') -Label $label -Executable 'C:\Program Files\WSL\wslc.exe' -TimeoutSeconds 12 -OutputDirectory $OutputDirectory -CommandArgs @('inspect',$ContainerId) | Out-Null
  $inspectDocument=Read-UploadDocument (Join-Path $OutputDirectory ($label+'.json'))
  $container=Assert-UploadContainer $uploadContext $creatorDocument.value $inspectDocument.value $ContainerId
 }
 if($remoteTransfer){
  $stageName=if($Artifact -eq 'fixture'){'stage-linux-fixture.json'}elseif($Artifact -eq 'launcher'){'stage-focus-fonts.json'}else{$null}
  if(-not $stageName){throw 'TRANSFER_STAGE_RECEIPT_REQUIRED'}
  $stageDocument=Read-UploadDocument (Join-Path $OutputDirectory $stageName)
  if($Artifact -eq 'fixture' -and ([IO.Path]::GetFullPath($stageDocument.value.target) -ine $sourcePath -or
   $stageDocument.value.sha256 -cne $hashBefore -or $stageDocument.value.bytes -ne $file.Length)){throw 'TRANSFER_STAGE_MISMATCH'}
  if($multiModuleProfile -and $Artifact -eq 'fixture'){
   if($Artifact -cne 'fixture' -or $stageDocument.value.wslc_profile -cne 'wslc_multi_module' -or
    $stageDocument.value.profile_kind -cne 'ModuleShell' -or
    $stageDocument.value.module_shell_source_manifest_sha256 -cne $moduleShellApproval.profile.module_shell.source_manifest_sha256 -or
    $stageDocument.value.module_shell_launch_settings_sha256 -cne $moduleShellLaunchSettingsDocument.ref.sha256 -or
    $stageDocument.value.artifact_id -cne $moduleShellApproval.artifact.artifact_id -or
    $stageDocument.value.source_commit -cne $moduleShellApproval.source_commit -or
    $stageDocument.value.native_build_receipt.sha256 -cne $moduleShellApproval.native_build_receipt.sha256 -or
    $stageDocument.value.sha256 -cne $moduleShellApproval.artifact.sha256 -or
    $stageDocument.value.bytes -ne $moduleShellApproval.artifact.bytes -or
    $moduleShellApproval.artifact.path -cne $uploadContext.module_shell_artifact_path){
    throw 'MODULE_SHELL_STAGE_BINDING_MISMATCH'
   }
  }
  if($Artifact -eq 'launcher'){
   Assert-RemoteFontArchiveStage -Stage $stageDocument.value -Artifact $Artifact -SourcePath $sourcePath `
    -ActualSha256 $hashBefore -ActualBytes $file.Length -ModuleShell $multiModuleProfile
  }
 }
 # Reuse only the initializer from the fixed existing capture helper. Do not
 # execute its CLI entry point or introduce another process owner/transport.
 $pumpTokens=$null;$pumpErrors=$null
 $pumpAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'capture-process.ps1'),[ref]$pumpTokens,[ref]$pumpErrors)
 if(@($pumpErrors).Count){throw 'UPLOAD_BOUNDED_READER_INVALID'}
 $pumpInit=$pumpAst.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Initialize-ToolkitBoundedOutput'},$true)
 if(-not $pumpInit){throw 'UPLOAD_BOUNDED_READER_INVALID'}
 . ([scriptblock]::Create($pumpInit.Extent.Text))
 Initialize-ToolkitBoundedOutput
 $outBuffer=[IO.MemoryStream]::new();$errBuffer=[IO.MemoryStream]::new();$outputCancel=[Threading.CancellationTokenSource]::new()
 [void]$process.Start()
 $out=[ToolkitBoundedOutput]::CopyBoundedAsync($process.StandardOutput.BaseStream,$outBuffer,1048576,$outputCancel.Token)
 $err=[ToolkitBoundedOutput]::CopyBoundedAsync($process.StandardError.BaseStream,$errBuffer,65536,$outputCancel.Token)
 $copy=$file.CopyToAsync($process.StandardInput.BaseStream)
 if(-not $copy.Wait(30000)){$process.Kill($true);throw 'Artifact upload timeout'}
 $process.StandardInput.Close()
 if(-not $process.WaitForExit(15000)){$process.Kill($true);throw 'Artifact upload process timeout'}
 if(-not $out.Wait(3000) -or -not $err.Wait(3000)){throw 'Artifact upload pipe drain failed'}
 $stdoutText=[Text.Encoding]::UTF8.GetString($outBuffer.ToArray());$stderrText=[Text.Encoding]::UTF8.GetString($errBuffer.ToArray())
 if($out.Result.Overflow -or $err.Result.Overflow -or $out.Result.Fault -or $err.Result.Fault){
  Write-UploadReceipt (Join-Path $OutputDirectory ($Artifact+'-output-refused.json')) `
   @{code='UPLOAD_OUTPUT_BOUND_OR_IO_FAILURE';outcome='OUTCOME_UNKNOWN';automatic_retry_allowed=$false;
     stdout=$stdoutText;stderr=$stderrText;stdout_overflow=$out.Result.Overflow;stderr_overflow=$err.Result.Overflow} $operationId
  throw 'UPLOAD_OUTPUT_BOUND_OR_IO_FAILURE'
 }
 $bytesSent=$file.Position;$file.Position=0
 $hash=[BitConverter]::ToString($hasher.ComputeHash($file)).Replace('-','')
 $fdAfter=Get-UploadFdStat $file
 Assert-UploadFdStable $fdBefore $fdAfter
 if($hash -cne $hashBefore -or $bytesSent -ne $file.Length -or $info.Length -ne $file.Length -or
  $process.ExitCode -ne 0 -or $stderrText -cne '' -or $stdoutText -cnotmatch ('\A(?i:'+$hash+')[ \t]+'+[regex]::Escape($target)+'(?:\r?\n)?\z')){throw 'Artifact hash mismatch or upload failure'}
 $record=[ordered]@{artifact=$Artifact;bytes=$info.Length;sha256=$hash;target=$target;exit_code=$process.ExitCode;stdout=$stdoutText;stderr=$stderrText;mounts_added=0}
 if($explicitContainerId){
  $record.container_id=$ContainerId
 }
 if($remoteTransfer){
  if((Read-UploadDocument (Join-Path $OutputDirectory 'context.json')).ref.sha256 -cne $contextDocument.ref.sha256 -or
   (Read-UploadDocument (Join-Path $OutputDirectory 'container-start.json')).ref.sha256 -cne $creatorDocument.ref.sha256){throw 'TRANSFER_CONTEXT_CHANGED'}
  $record.provenance=[ordered]@{schema='toolkit-wslc-artifact-transfer-provenance-v1';operation_id=$operationId;
   started_utc=$startedUtc;completed_utc=[DateTimeOffset]::UtcNow.ToString('o');
   source=@{path=$sourcePath;bytes_sent=$bytesSent;fd_before=$fdBefore;fd_after=$fdAfter;sha256_before=$hashBefore;sha256_after=$hash};
   stage_receipt=$stageDocument.ref;context=$contextDocument.ref;creator_receipt=$creatorDocument.ref;container_inspect_receipt=$inspectDocument.ref;
   container=$container;guest=@{path=$target;bytes=$bytesSent;sha256=$hash}}
   if($multiModuleProfile){
    $preparationDocument=Read-UploadDocument (Join-Path $OutputDirectory 'module-shell-build-approval.json')
    if($preparationDocument.ref.sha256 -cne $moduleShellPreparationDocument.ref.sha256 -or
     (Read-UploadDocument (Join-Path $OutputDirectory 'module-shell-launch-settings.json')).ref.sha256 -cne $moduleShellLaunchSettingsDocument.ref.sha256 -or
     (Read-UploadDocument (Join-Path $OutputDirectory 'module-shell-host-admission.json')).ref.sha256 -cne $moduleShellHostAdmissionDocument.ref.sha256){
     throw 'MODULE_SHELL_PREPARATION_RECEIPT_CHANGED'
    }
    $record.provenance.module_shell_preparation=[ordered]@{
     schema='toolkit-makepad-dev-app-module-shell-wslc-preparation-v1';
     preparation_receipt=$preparationDocument.ref;profile_id=$moduleShellApproval.profile_id;
     profile_kind=$moduleShellApproval.profile.profile_kind;
     module_shell_source_manifest_sha256=$moduleShellApproval.profile.module_shell.source_manifest_sha256;
     profile=$moduleShellApproval.profile;
     source_commit=$moduleShellApproval.source_commit;build_receipt=$moduleShellApproval.build_receipt;
     native_build_receipt=$moduleShellApproval.native_build_receipt;
     source_manifest=$moduleShellApproval.source_manifest;artifact=$moduleShellApproval.artifact;
     host_admission_receipt=$moduleShellHostAdmissionDocument.ref;
     launch_settings_receipt=$moduleShellLaunchSettingsDocument.ref;
     launch_settings=$launchSettings;
     guest_home_directory=[ordered]@{path=$moduleShellMakepadHome;created_by_transfer=($Artifact -eq 'fixture');mode='0700';fresh_container_local=$true}
    }
    $record.module_shell_launch=[ordered]@{profile_kind='ModuleShell';
     makepad_home=$moduleShellMakepadHome;project_id=$moduleShellProjectId;native_late_probe=$moduleShellLateProbe;
     container_environment_inspected=$true;home_directory_created=($Artifact -eq 'fixture');home_directory_mode='0700';
     status='PREPARED_NOT_RUNTIME_ACCEPTANCE'}
   }
 }
 Write-UploadReceipt (Join-Path $OutputDirectory ($Artifact+'-upload.json')) $record $operationId
 $record|ConvertTo-Json -Depth 24
}finally{
 $hasher.Dispose();$file.Dispose();try{if(-not $process.HasExited){$process.Kill($true)}}catch{}
 if($outputCancel){$outputCancel.Cancel();$outputCancel.Dispose()}
 if($outBuffer){$outBuffer.Dispose()};if($errBuffer){$errBuffer.Dispose()};$process.Dispose()
}
