param([string]$OutputDirectory=(Join-Path $PSScriptRoot '../../reports/evidence/ai-execution-workspace-2026-10-08'),[switch]$ConnectTrustedDefaultSession,[ValidateSet('cad_3d','heavy_viewer','ui_smoke','gpu_nvidia_test')][string]$GpuProfile='ui_smoke',
 [ValidateSet('legacy','makepad_remote71')][string]$RuntimeProfile='legacy',[string]$Owner,
 [ValidateSet('text_input71','focus_trace71','module_shell71')][string]$RemoteFixture='text_input71',
 [ValidateSet('single_app','multi_module')][string]$WslcProfile='single_app',
 [string]$ModuleShellBuildManifest,[string]$ModuleShellBuildManifestSha256,[string]$ApprovedModuleShellElf,
 [ValidateSet('none','remote_api_adoption_v1')][string]$ResourceAuthorization='none')
$ErrorActionPreference='Stop'
$out=[IO.Path]::GetFullPath($OutputDirectory)
$remoteProfile=$RuntimeProfile -eq 'makepad_remote71'
$expectedImage='sha256:219e68c9b9ff3c0e24f8a2e937abe08beb98ebd2c88d551f25f09b052ff2107b'
$approvedFixtureSha256='C989BFA10615A839B61A2D6D8D4D7C04501CC7B62559241A32846D53BC5DC48C'
$remoteSourceRevision='71c9ddcbb9c01dd208f99621fdd71024a5d35c65'
$moduleShellMakepadHome='/tmp/toolkit-module-shell-wslc-home'
$moduleShellProjectId='module-shell-wslc-v1'
$moduleShellLateProbe='1'
function Write-BootstrapJson([string]$Name,$Value){
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 12))
 $stream=[IO.FileStream]::new((Join-Path $out $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
}
function Get-RemoteCreatedContainerId($Creator,[string]$Executable,[string[]]$ExpectedArgs){
 # Creation authorizes failure containment, NOT inspection approval or uploads.
 # Never turn a failed/ambiguous run's CID-looking stdout into stop authority.
 if($null -eq $Creator -or $null -eq $ExpectedArgs -or $ExpectedArgs.Count -eq 0){return $null}
 foreach($name in @('label','executable','args','exit_code','timed_out','output_drained','owned_tree_termination_requested','stdout')){
  if($null -eq $Creator.PSObject.Properties[$name]){return $null}
 }
 if($Creator.label -cne 'container-start' -or $Creator.executable -isnot [string] -or
  -not [string]::Equals($Creator.executable,$Executable,[StringComparison]::OrdinalIgnoreCase) -or
  -not ($Creator.exit_code -is [int] -or $Creator.exit_code -is [long]) -or $Creator.exit_code -ne 0 -or
  $Creator.timed_out -isnot [bool] -or $Creator.timed_out -ne $false -or
  $Creator.output_drained -isnot [bool] -or $Creator.output_drained -ne $true -or
  $Creator.owned_tree_termination_requested -isnot [bool] -or $Creator.owned_tree_termination_requested -ne $false -or
  $Creator.args -isnot [array] -or $Creator.args.Count -ne $ExpectedArgs.Count -or $Creator.stdout -isnot [string]){return $null}
 for($index=0;$index -lt $ExpectedArgs.Count;$index++){
  if($Creator.args[$index] -isnot [string] -or $Creator.args[$index] -cne $ExpectedArgs[$index]){return $null}
 }
 $created=$Creator.stdout.Trim()
 if($created -cnotmatch '^[a-f0-9]{64}$'){return $null}
 return $created
}
function Assert-ModuleShellContainerEnvironment($Config){
 $expected=@("MAKEPAD_HOME=$moduleShellMakepadHome","TOOLKIT_MODULE_PROJECT_ID=$moduleShellProjectId",
  "TOOLKIT_NATIVE_LATE_PROBE=$moduleShellLateProbe")
 if($Config.Env -isnot [array]){throw 'MODULE_SHELL_CONTAINER_ENVIRONMENT_MISSING'}
 foreach($entry in $expected){
  $key=$entry.Substring(0,$entry.IndexOf('=')+1)
  $matches=@($Config.Env|Where-Object {$_ -is [string] -and $_.StartsWith($key,[StringComparison]::Ordinal)})
  if($matches.Count -ne 1 -or $matches[0] -cne $entry){throw 'MODULE_SHELL_CONTAINER_ENVIRONMENT_MISMATCH'}
 }
}
function Get-ModuleShellActiveCompilers($Processes){
 @($Processes|Where-Object {
  if($_.Name -ieq 'rustc.exe'){return $true}
  if($_.Name -ine 'cargo.exe'){return $false}
  return -not ($_.CommandLine -match '(?i)(?:^|\s)run(?:\s|$)' -and
   $_.CommandLine -match '--bin\s+toolkit-windows-gui-mcp(?:\s|$)' -and
   $_.CommandLine -notmatch '(?i)(?:^|\s)(build|test|check|bench|rustc)(?:\s|$)')
 })
}
function Test-RemoteResourceAuthorizationScope([string]$Profile,[string]$ResourceOwner,[string]$Key){
 if($Key -ceq 'none'){return $false}
 if($Key -cne 'remote_api_adoption_v1' -or $Profile -cne 'makepad_remote71' -or
  $ResourceOwner -cne 'Makepad_Toolkit:remote-api-adoption-v1'){throw 'REMOTE_RESOURCE_AUTHORIZATION_SCOPE_REFUSED'}
 return $true
}
function Assert-RemoteAdmissionJsonUnique([System.Text.Json.JsonElement]$Element){
 if($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object){
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach($property in $Element.EnumerateObject()){
   if(-not $names.Add($property.Name)){throw 'REMOTE_ADMISSION_DUPLICATE_KEY'}
   Assert-RemoteAdmissionJsonUnique $property.Value
  }
 }elseif($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array){
  foreach($item in $Element.EnumerateArray()){Assert-RemoteAdmissionJsonUnique $item}
 }
}
function Get-RemoteAdmissionSha256([byte[]]$Bytes){
 $digest=[Security.Cryptography.SHA256]::Create()
 try{return [BitConverter]::ToString($digest.ComputeHash($Bytes)).Replace('-','')}finally{$digest.Dispose()}
}
function Read-RemoteAdmissionBytes([string]$Path,[int]$Cap){
 # Only fixed stock/grant/fixture-manifest files call this loader. Hold a read-only handle;
 # cap DURING the read, and refuse every reparse ancestor before opening it.
 $item=Get-Item -LiteralPath $Path -Force
 if($item.PSIsContainer){throw 'REMOTE_ADMISSION_FILE_TYPE_REFUSED'}
 for($part=$item;$null -ne $part;){
  if(($part.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'REMOTE_ADMISSION_REPARSE_REFUSED'}
  $part=if($part -is [IO.FileInfo]){$part.Directory}else{$part.Parent}
 }
 $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  $length=$stream.Length
  if($length -gt $Cap){throw 'REMOTE_ADMISSION_FILE_BOUND'}
  $buffer=[byte[]]::new($Cap+1);$count=0
  while($count -lt $buffer.Length){
   $read=$stream.Read($buffer,$count,$buffer.Length-$count)
   if($read -eq 0){break};$count+=$read
  }
  if($count -ne $length -or $count -gt $Cap -or $stream.Length -ne $length){throw 'REMOTE_ADMISSION_FILE_CHANGED'}
  $raw=[byte[]]::new($count);[Array]::Copy($buffer,$raw,$count)
  return ,$raw
 }finally{$stream.Dispose()}
}
function New-RemoteScopedRuntimeAdmission([byte[]]$StockBytes,[byte[]]$AuthorizationBytes,
 [string]$Profile,[string]$ResourceOwner,[string]$Key,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow){
 if(-not (Test-RemoteResourceAuthorizationScope $Profile $ResourceOwner $Key)){throw 'REMOTE_RESOURCE_AUTHORIZATION_REQUIRED'}
 if($null -eq $StockBytes -or $StockBytes.Length -gt 65536 -or
  $null -eq $AuthorizationBytes -or $AuthorizationBytes.Length -gt 16384){throw 'REMOTE_ADMISSION_BYTES_BOUND'}
 $encoding=[Text.UTF8Encoding]::new($false,$true)
 $stockRaw=$encoding.GetString($StockBytes);$authorizationRaw=$encoding.GetString($AuthorizationBytes)
 $authorizationSha=Get-RemoteAdmissionSha256 $AuthorizationBytes
 if($authorizationSha -cne '1D9BD6C43D7EBFDF550CE99BE7D6E9C4A0A0C1D7951D25F0B3331F548B6F1546'){throw 'REMOTE_RESOURCE_AUTHORIZATION_PIN_REFUSED'}
 $stockDoc=$null;$authorizationDoc=$null
 try{
  $stockDoc=[System.Text.Json.JsonDocument]::Parse($stockRaw)
  $authorizationDoc=[System.Text.Json.JsonDocument]::Parse($authorizationRaw)
  Assert-RemoteAdmissionJsonUnique $stockDoc.RootElement
  Assert-RemoteAdmissionJsonUnique $authorizationDoc.RootElement
  $stock=$stockDoc.RootElement;$grant=$authorizationDoc.RootElement
  if($stock.ValueKind -ne [System.Text.Json.JsonValueKind]::Object -or
   $grant.ValueKind -ne [System.Text.Json.JsonValueKind]::Object){throw 'REMOTE_ADMISSION_JSON_OBJECT_REQUIRED'}
  foreach($property in $stock.EnumerateObject()){
   if($property.Name -match '(?i)waiver'){throw 'REMOTE_ADMISSION_WAIVER_REFUSED'}
  }
  $strings=@{schema='toolkit-scoped-operator-resource-authorization-v1';milestone='MAKEPAD_DEV_REMOTE_API_ADOPTION_V1';
   operator_quote='Игнорируй нехваток памяти';thread_id='01a00532-be65-7723-89ec-c1b2bfdd373e';
   scope='RAM-only admission exception for continuing this milestone; not a global policy change'}
  foreach($name in $strings.Keys){
   if($grant.GetProperty($name).GetString() -cne $strings[$name]){throw 'REMOTE_RESOURCE_AUTHORIZATION_SCOPE_REFUSED'}
  }
  foreach($name in @('actual_memory_observation_required','stock_admission_results_must_not_be_relabelled')){
   if($grant.GetProperty($name).ValueKind -ne [System.Text.Json.JsonValueKind]::True){throw 'REMOTE_RESOURCE_AUTHORIZATION_SCOPE_REFUSED'}
  }
  foreach($name in @('global_resource_policy_changed','runtime_acceptance_claimed')){
   if($grant.GetProperty($name).ValueKind -ne [System.Text.Json.JsonValueKind]::False){throw 'REMOTE_RESOURCE_AUTHORIZATION_SCOPE_REFUSED'}
  }
  if($stock.GetProperty('purpose').GetString() -cne 'runtime' -or
   $stock.GetProperty('active_rust_compilers').ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or
   $stock.GetProperty('active_rust_compilers').GetArrayLength() -ne 0){throw 'REMOTE_STOCK_ADMISSION_REQUIRED'}
  foreach($name in @('free_physical_kib','required_free_kib')){
   $number=$stock.GetProperty($name)
   if($number.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or
    $number.GetRawText() -cnotmatch '^(?:0|[1-9][0-9]*)$'){throw 'REMOTE_STOCK_MEMORY_INVALID'}
   [void]$number.GetUInt64()
  }
  $free=$stock.GetProperty('free_physical_kib').GetUInt64()
  if($stock.GetProperty('required_free_kib').GetUInt64() -ne 2097152){throw 'REMOTE_STOCK_THRESHOLD_CHANGED'}
  $expectedStatus=if($free -lt 2097152){'BLOCKED_ENVIRONMENT'}else{'ADMITTED'}
  if($stock.GetProperty('status').GetString() -cne $expectedStatus){throw 'REMOTE_STOCK_STATUS_INCONSISTENT'}
  $utc=$stock.GetProperty('utc').GetString();$observed=[DateTimeOffset]::MinValue
  if($utc -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$' -or
   -not [DateTimeOffset]::TryParse($utc,[Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::None,[ref]$observed)){throw 'REMOTE_STOCK_UTC_INVALID'}
  $age=($Now-$observed).TotalMilliseconds
  if($age -lt 0 -or $age -gt 120000){throw 'REMOTE_ADMISSION_STALE'}
  $envelope=[ordered]@{schema='toolkit-remote-scoped-runtime-admission-v1';
   stock=[ordered]@{path='runtime-admission.json';sha256=(Get-RemoteAdmissionSha256 $StockBytes);raw_utf8=$stockRaw};
   authorization=[ordered]@{path='reports/evidence/makepad-dev-remote-api-adoption-v1/quality-26/operator-memory-authorization.json';
    sha256=$authorizationSha;raw_utf8=$authorizationRaw}}
  if($encoding.GetByteCount(($envelope|ConvertTo-Json -Depth 12)) -gt 65536){throw 'REMOTE_ADMISSION_ENVELOPE_BOUND'}
  return $envelope
 }finally{
  if($null -ne $stockDoc){$stockDoc.Dispose()};if($null -ne $authorizationDoc){$authorizationDoc.Dispose()}
 }
}
function Get-RemoteFocusFontContract($Manifest,[string]$ManifestSha256,$ManifestBytes,[string]$ArchiveSha256,$ArchiveBytes){
 if($ManifestSha256 -cne '6288DAA9A209B6741D6AEE02387F0ABE201F02A223223C06A99395EE271F92B1' -or
  $ArchiveSha256 -cne '394798AFC3B47F508A9D1A1DD7B50D1465B81BC2906A91F8F8A04AD5A3E30CEA' -or
  -not ($ManifestBytes -is [int] -or $ManifestBytes -is [long]) -or $ManifestBytes -le 0 -or $ManifestBytes -gt 16384 -or
  -not ($ArchiveBytes -is [int] -or $ArchiveBytes -is [long]) -or $ArchiveBytes -ne 49539584){throw 'REMOTE_FOCUS_FONT_PIN_OR_BOUND_REFUSED'}
 $target='/opt/makepad-operator/.cache/makepad-dev-pilot-20261015/source-71c9ddc/widgets/resources'
 if($Manifest.source_sha -cne '71c9ddcbb9c01dd208f99621fdd71024a5d35c65' -or
  $Manifest.archive_sha256 -cne $ArchiveSha256 -or $Manifest.target_directory -cne $target){throw 'REMOTE_FOCUS_FONT_SOURCE_REFUSED'}
 $names=@('IBMPlexSans-Text.ttf','IBMPlexSans-SemiBold.ttf','IBMPlexSans-Italic.ttf','IBMPlexSans-BoldItalic.ttf',
  'LiberationMono-Regular.ttf','fa-solid-900.ttf','LXGWWenKaiRegular.ttf','LXGWWenKaiBold.ttf','NotoColorEmoji.ttf')
 if($Manifest.files -isnot [array] -or $Manifest.files.Count -ne $names.Count){throw 'REMOTE_FOCUS_FONT_ALLOWLIST_REFUSED'}
 $files=@(for($i=0;$i -lt $names.Count;$i++){
  $file=$Manifest.files[$i]
  if($file.name -cne $names[$i] -or $file.sha256 -isnot [string] -or $file.sha256 -cnotmatch '^[0-9A-F]{64}$' -or
   -not ($file.bytes -is [int] -or $file.bytes -is [long]) -or $file.bytes -le 0 -or $file.bytes -gt 64MB){throw 'REMOTE_FOCUS_FONT_ALLOWLIST_REFUSED'}
  # Deliberately omit each historical host `source` path. It is not command input.
  [ordered]@{name=$names[$i];bytes=$file.bytes;sha256=$file.sha256}
 })
 return [ordered]@{source_sha=$Manifest.source_sha;manifest_sha256=$ManifestSha256;
  archive_sha256=$ArchiveSha256;archive_bytes=$ArchiveBytes;target_directory=$target;files=$files}
}
function Assert-RemoteFocusFontListing($Receipt,$Contract){
 if(-not ($Receipt.exit_code -is [int] -or $Receipt.exit_code -is [long]) -or $Receipt.exit_code -ne 0 -or
  $Receipt.timed_out -isnot [bool] -or $Receipt.timed_out -or $Receipt.output_drained -isnot [bool] -or -not $Receipt.output_drained -or
  $Receipt.stdout -isnot [string] -or $Receipt.stderr -cne ''){throw 'REMOTE_FOCUS_FONT_LIST_FAILED'}
 $text=$Receipt.stdout
 if($text.EndsWith("`r`n")){$text=$text.Substring(0,$text.Length-2)}elseif($text.EndsWith("`n")){$text=$text.Substring(0,$text.Length-1)}
 $listed=@($text -split '\r?\n')
 if($listed.Count -ne 9){throw 'REMOTE_FOCUS_FONT_LIST_REFUSED'}
 for($i=0;$i -lt 9;$i++){if($listed[$i] -cne $Contract.files[$i].name){throw 'REMOTE_FOCUS_FONT_LIST_REFUSED'}}
}
if($remoteProfile){
 if([string]::IsNullOrWhiteSpace($Owner) -or [Text.Encoding]::UTF8.GetByteCount($Owner) -gt 128 -or $Owner -match '[\x00-\x1f\x7f]'){throw 'REMOTE_OWNER_REQUIRED_BOUNDED'}
 if($PSBoundParameters.ContainsKey('GpuProfile') -and $GpuProfile -ne 'gpu_nvidia_test'){throw 'REMOTE_REQUIRED_GPU_PROFILE'}
 $GpuProfile='gpu_nvidia_test'
 $evidenceRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../reports/evidence'))+[IO.Path]::DirectorySeparatorChar
 if(-not $out.StartsWith($evidenceRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Evidence scope refused'}
 if(Test-Path -LiteralPath $out){throw 'Fresh remote output directory required'}
 $nonce=[Guid]::NewGuid().ToString('N')
}elseif($PSBoundParameters.ContainsKey('Owner')){throw 'OWNER_REQUIRES_REMOTE_PROFILE'}
if(-not $remoteProfile -and $PSBoundParameters.ContainsKey('RemoteFixture')){throw 'REMOTE_FIXTURE_REQUIRES_REMOTE_PROFILE'}
if(-not $remoteProfile -and $PSBoundParameters.ContainsKey('ResourceAuthorization')){throw 'RESOURCE_AUTHORIZATION_REQUIRES_REMOTE_PROFILE'}
$multiModuleProfile=$WslcProfile -ceq 'multi_module'
$moduleShellArgumentsSupplied=$PSBoundParameters.ContainsKey('ModuleShellBuildManifest') -or
 $PSBoundParameters.ContainsKey('ModuleShellBuildManifestSha256') -or $PSBoundParameters.ContainsKey('ApprovedModuleShellElf')
if($multiModuleProfile){
 if(-not $PSBoundParameters.ContainsKey('WslcProfile') -or -not $remoteProfile -or
  -not $PSBoundParameters.ContainsKey('RemoteFixture') -or $RemoteFixture -cne 'module_shell71' -or
  [string]::IsNullOrWhiteSpace($ModuleShellBuildManifest) -or
  [string]::IsNullOrWhiteSpace($ModuleShellBuildManifestSha256) -or
  [string]::IsNullOrWhiteSpace($ApprovedModuleShellElf) -or $ResourceAuthorization -cne 'none'){
  throw 'MODULE_SHELL_OPERATOR_OPT_IN_REQUIRED'
 }
}elseif($RemoteFixture -ceq 'module_shell71' -or $moduleShellArgumentsSupplied){
 throw 'MODULE_SHELL_ARGUMENTS_REQUIRE_MULTI_MODULE_OPT_IN'
}
$moduleShellApproval=$null
if($multiModuleProfile){
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
  $moduleShellApproval.profile_id -cne 'wslc_multi_module' -or
  $moduleShellApproval.profile.profile_id -cne 'wslc_multi_module' -or
  $moduleShellApproval.profile.profile_kind -cne 'ModuleShell' -or
  $moduleShellApproval.profile.module_shell.source_manifest_sha256 -cne $moduleShellApproval.source_manifest.sha256 -or
  $moduleShellApproval.profile.module_instances -ne 2 -or
  $moduleShellApproval.profile.container.memory_bytes -ne 2147483648 -or
  $moduleShellApproval.profile.container.cpus -ne 1 -or
  $moduleShellApproval.profile.host_runtime_admission.minimum_free_bytes -ne 2684354560 -or
  $moduleShellApproval.profile.host_runtime_admission.host_ram_mode -cne 'USER_WAIVED' -or
  $moduleShellApproval.profile.host_runtime_admission.nested_increment_bytes -ne 0 -or
  $moduleShellApproval.native_build_receipt.path -cne 'reports/evidence/toolkit-makepad-dev-module-lifecycle-v1/wslc-hot-reload/linux-build05/native/module-shell-build.json' -or
  $moduleShellApproval.native_build_receipt.sha256 -cnotmatch '^[0-9A-F]{64}$' -or
  $moduleShellApproval.artifact.artifact_id -cne 'makepad-dev-app-module-shell-linux-71c9ddc'){
  throw 'MODULE_SHELL_PREPARATION_OUTPUT_INVALID'
 }
}
$useScopedAdmission=Test-RemoteResourceAuthorizationScope $RuntimeProfile $Owner $ResourceAuthorization
# Storage admission is independent from RAM waivers. No ELF copy, upload,
# container create, or GPU work can precede a versioned storage decision.
$storagePython=Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
if(-not (Test-Path -LiteralPath $storagePython -PathType Leaf)){throw 'TRUSTED_STORAGE_PYTHON_UNAVAILABLE'}
$storageArgs=@('-B',(Join-Path $PSScriptRoot 'storage_policy.py'),'--admit-create',(Join-Path $out 'storage'))
if($RuntimeProfile -ceq 'makepad_remote71' -and $RemoteFixture -ceq 'focus_trace71' -and $WslcProfile -ceq 'single_app'){
 $storageArgs+=@('--profile','focus_trace71')
}
& $storagePython @storageArgs | Out-Null
if($LASTEXITCODE -ne 0){
 $storage=Get-Content -LiteralPath (Join-Path $out 'storage/storage-admission.json') -Raw|ConvertFrom-Json
 throw ([string]$storage.decision.code)
}
. (Join-Path $PSScriptRoot 'gpu-policy.ps1')
$gpu=Invoke-WorkspaceGpuPolicy 'resolve' $GpuProfile
if($multiModuleProfile){
 $moduleShellCompilerProcesses=@(Get-CimInstance Win32_Process|
  Where-Object {$_.Name -ieq 'rustc.exe' -or $_.Name -ieq 'cargo.exe'}|
  Select-Object ProcessId,Name,CommandLine)
 $moduleShellCompilers=@(Get-ModuleShellActiveCompilers $moduleShellCompilerProcesses)
 if($moduleShellCompilers.Count -gt 0){throw 'BLOCKED_ENVIRONMENT: active Rust compiler or build'}
 [void][IO.Directory]::CreateDirectory($out)
 $multiModuleAdmission=[ordered]@{schema='toolkit-makepad-dev-app-module-shell-host-admission-v1';
  utc=[DateTime]::UtcNow.ToString('o');owner=$Owner;source_manifest_sha256=$moduleShellApproval.source_manifest.sha256;
  host_ram_mode='USER_WAIVED';status='USER_WAIVED';available_memory_query_performed=$false;
  minimum_free_bytes=2684354560;minimum_free_kib=2621440;
  container_memory_bytes=2147483648;container_cpus=1;nested_increment_kib=0;
  active_compiler_observation_performed=$true;active_rust_compilers=$moduleShellCompilers;
  resource_admitted=$false;scope='one_outer_runtime_admission'}
 Write-BootstrapJson 'module-shell-build-approval.json' $moduleShellApproval
 $moduleShellApprovalSha256=(Get-FileHash -LiteralPath (Join-Path $out 'module-shell-build-approval.json') -Algorithm SHA256).Hash
 Write-BootstrapJson 'module-shell-host-admission.json' $multiModuleAdmission
 $moduleShellLaunchSettings=[ordered]@{schema='toolkit-makepad-dev-app-module-shell-launch-settings-v1';
  status='PREPARED_NOT_RUNTIME_ACCEPTANCE';profile_kind='ModuleShell';
  makepad_home=$moduleShellMakepadHome;project_id=$moduleShellProjectId;native_late_probe=$moduleShellLateProbe;
  fresh_container_required=$true;home_scope='owned_container_local';home_directory_mode='0700';
  late_probe_scope='one_shell_lifecycle';public_ai_environment_used=$false}
 Write-BootstrapJson 'module-shell-launch-settings.json' $moduleShellLaunchSettings
 $moduleShellLaunchSettingsSha256=(Get-FileHash -LiteralPath (Join-Path $out 'module-shell-launch-settings.json') -Algorithm SHA256).Hash
}else{
 & (Join-Path $PSScriptRoot 'preflight.ps1') -Purpose runtime -OutputDirectory $out | Out-Null
 $admission=Get-Content (Join-Path $out 'runtime-admission.json') -Raw|ConvertFrom-Json
 if($useScopedAdmission){
  $stockBytes=Read-RemoteAdmissionBytes (Join-Path $out 'runtime-admission.json') 65536
  $authorizationBytes=Read-RemoteAdmissionBytes (Join-Path $PSScriptRoot '../../reports/evidence/makepad-dev-remote-api-adoption-v1/quality-26/operator-memory-authorization.json') 16384
  $scopedAdmission=New-RemoteScopedRuntimeAdmission $stockBytes $authorizationBytes $RuntimeProfile $Owner $ResourceAuthorization
  Write-BootstrapJson 'scoped-runtime-admission.json' $scopedAdmission
  [Console]::Error.WriteLine($(if($admission.status -eq 'BLOCKED_ENVIRONMENT'){'AUTHORIZED_SCOPED_RAM_EXCEPTION'}else{'STOCK_ADMITTED'}))
 }elseif($admission.status -ne 'ADMITTED'){throw 'BLOCKED_ENVIRONMENT: no WSLC runtime admission'}
}
if(Test-Path (Join-Path $out 'context.json')){throw 'Existing context is not resumable; inspect its cleanup before using a fresh proof directory'}
$wslc='C:\Program Files\WSL\wslc.exe'
# Inventory sessions before `ps`: container commands may create the default VM.
$sessions=(& $wslc system session list --verbose) -join "`n"
if($LASTEXITCODE -ne 0){throw 'Session inventory failed'}
$sessionPreexisting=($sessions -notmatch 'Found 0 sessions')
if($sessionPreexisting -and (-not $ConnectTrustedDefaultSession -or $sessions -notmatch 'Found 1 session' -or $sessions -notmatch ('wslc-cli-'+[regex]::Escape($env:USERNAME)))){throw 'Existing WSLC session requires explicit trusted default-session connection'}
$inventory=& $wslc ps -a
if($remoteProfile){
 if($LASTEXITCODE -ne 0 -or @($inventory).Count -lt 1){throw 'Container inventory failed'}
 # Other names convey no ownership and are never stopped or adopted.
 if(($inventory -join "`n") -match '(?m)(?:^|\s)aiui-workspace-20261008(?:\s|$)'){throw 'FIXED_CONTAINER_NAME_CONFLICT'}
}elseif($LASTEXITCODE -ne 0 -or @($inventory).Count -ne 1){throw 'Default-session connection requires an empty container inventory'}
Write-BootstrapJson 'session-connection.json' ([ordered]@{utc=[DateTime]::UtcNow.ToString('o');session_inventory_before=$sessions;container_inventory_before=$inventory;preexisting=$sessionPreexisting;trusted_connection=$ConnectTrustedDefaultSession.IsPresent;owns_vm=$false;vm_cleanup_policy='Never terminate the connected default session; clean only the exact experiment-owned container'})
$capture=Join-Path $PSScriptRoot 'capture-process.ps1'
$ownedId=$null;$createdId=$null;$id=$null
try{
 if($remoteProfile){
  # Fixed approved host artifact only: no WSL staging, build or source override.
  switch($RemoteFixture){
   'text_input71' {$approvedFixtureRelative='../../reports/evidence/makepad-dev-integration-pilot-20261015/runtime-ram-waiver-1/linux-makepad-example-text-input'}
   'focus_trace71' {
    $approvedFixtureRelative='../../reports/evidence/makepad-dev-remote-api-adoption-v1/linux-focus-build-34/linux-toolkit-remote-focus-trace-fixture'
    $approvedFixtureSha256='9DFA4EEC8D4FEE6CAEE509D4FF2ACCB5136FED3A1D64D2302F0E35FF623AA4CB'
   }
    'module_shell71' {
     if(-not $multiModuleProfile -or $null -eq $moduleShellApproval){throw 'MODULE_SHELL_OPERATOR_OPT_IN_REQUIRED'}
     $approvedFixture=Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))) $moduleShellApproval.artifact.path
     $approvedFixtureSha256=$moduleShellApproval.artifact.sha256
    }
   default {throw 'REMOTE_FIXTURE_CHOICE_INVALID'}
  }
   if($RemoteFixture -cne 'module_shell71'){$approvedFixture=Join-Path $PSScriptRoot $approvedFixtureRelative}
  $stagedFixture=Join-Path $out 'ai-workspace-fixture'
  $stagingDrive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($out))
  if($stagingDrive.AvailableFreeSpace-(Get-Item -LiteralPath $approvedFixture).Length -lt 10000000000){throw 'HOST_SSD_RESERVE_VIOLATED'}
  $fixtureStream=[IO.FileStream]::new($approvedFixture,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  $hasher=[Security.Cryptography.SHA256]::Create()
  try{
   $before=Get-Item -LiteralPath $approvedFixture
   if($fixtureStream.Length -le 0 -or $before.Length -ne $fixtureStream.Length -or
    ($multiModuleProfile -and ($null -eq $moduleShellApproval -or $fixtureStream.Length -ne $moduleShellApproval.artifact.bytes -or $fixtureStream.Length -gt 512MB)) -or
    (-not $multiModuleProfile -and $fixtureStream.Length -gt 128MB)){throw 'APPROVED_ELF_SIZE_REFUSED'}
   $beforeHash=[BitConverter]::ToString($hasher.ComputeHash($fixtureStream)).Replace('-','')
   if($beforeHash -cne $approvedFixtureSha256){throw 'APPROVED_ELF_HASH_MISMATCH'}
   $fixtureStream.Position=0
   $destination=[IO.FileStream]::new($stagedFixture,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$fixtureStream.CopyTo($destination,65536)}finally{$destination.Dispose()}
   $fixtureStream.Position=0
   $afterHash=[BitConverter]::ToString($hasher.ComputeHash($fixtureStream)).Replace('-','')
   $after=Get-Item -LiteralPath $approvedFixture
   $stagedHash=(Get-FileHash -LiteralPath $stagedFixture -Algorithm SHA256).Hash
   if($afterHash -cne $approvedFixtureSha256 -or $stagedHash -cne $approvedFixtureSha256 -or $before.Length -ne $after.Length -or $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks -or (Get-Item -LiteralPath $stagedFixture).Length -ne $before.Length){throw 'APPROVED_ELF_CHANGED_DURING_STAGE'}
    $stageReceipt=[ordered]@{source=$approvedFixture;target=$stagedFixture;bytes=$before.Length;sha256=$stagedHash;remote_fixture=$RemoteFixture;scope='HOST_ARTIFACT_COPY_NOT_RUNTIME_PROOF'}
    if($multiModuleProfile){
     $stageReceipt.wslc_profile='wslc_multi_module';$stageReceipt.artifact_id=$moduleShellApproval.artifact.artifact_id
     $stageReceipt.profile_kind=$moduleShellApproval.profile.profile_kind
     $stageReceipt.module_shell_source_manifest_sha256=$moduleShellApproval.profile.module_shell.source_manifest_sha256
     $stageReceipt.module_shell_launch_settings_sha256=$moduleShellLaunchSettingsSha256
     $stageReceipt.module_instances=$moduleShellApproval.profile.module_instances
     $stageReceipt.source_commit=$moduleShellApproval.source_commit
     $stageReceipt.build_receipt=$moduleShellApproval.build_receipt
     $stageReceipt.native_build_receipt=$moduleShellApproval.native_build_receipt
     $stageReceipt.source_manifest=$moduleShellApproval.source_manifest
    }
    Write-BootstrapJson 'stage-linux-fixture.json' $stageReceipt
  }finally{$hasher.Dispose();$fixtureStream.Dispose()}
 if($remoteProfile -and $RemoteFixture -in @('focus_trace71','module_shell71')){
   # Use the fixed historical ARTIFACTS contract; never call its preparer or launcher.
   $fontManifestPath=Join-Path $PSScriptRoot '../../reports/evidence/makepad-dev-remote-adapter-acceptance-20261016/wslc-attempt-17/runtime-assets.json'
   $fontArchivePath=Join-Path $PSScriptRoot '../../reports/evidence/makepad-dev-remote-adapter-acceptance-20261016/wslc-attempt-17/runtime-font-assets.tar'
   $fontManifestRaw=Read-RemoteAdmissionBytes $fontManifestPath 16384
   $fontManifestSha=Get-RemoteAdmissionSha256 $fontManifestRaw
   $fontManifest=([Text.UTF8Encoding]::new($false,$true).GetString($fontManifestRaw))|ConvertFrom-Json
   $fontStream=[IO.FileStream]::new($fontArchivePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
   $fontHasher=[Security.Cryptography.SHA256]::Create()
   try{
    if($fontStream.Length -ne 49539584){throw 'REMOTE_FOCUS_FONT_ARCHIVE_BOUND'}
    $fontArchiveSha=[BitConverter]::ToString($fontHasher.ComputeHash($fontStream)).Replace('-','')
    $fontContract=Get-RemoteFocusFontContract $fontManifest $fontManifestSha $fontManifestRaw.Length $fontArchiveSha $fontStream.Length
    $stagedFonts=Join-Path $out 'runtime-font-assets.tar'
    $fontStream.Position=0
    $fontDestination=[IO.FileStream]::new($stagedFonts,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$fontStream.CopyTo($fontDestination,65536)}finally{$fontDestination.Dispose()}
    $fontStream.Position=0
    if([BitConverter]::ToString($fontHasher.ComputeHash($fontStream)).Replace('-','') -cne $fontContract.archive_sha256 -or
     (Get-Item -LiteralPath $stagedFonts).Length -ne $fontContract.archive_bytes -or
     (Get-FileHash -LiteralPath $stagedFonts -Algorithm SHA256).Hash -cne $fontContract.archive_sha256){throw 'REMOTE_FOCUS_FONT_STAGE_DRIFT'}
    Write-BootstrapJson 'stage-focus-fonts.json' @{manifest_source=$fontManifestPath;archive_source=$fontArchivePath;
     staged_archive=$stagedFonts;contract=$fontContract;scope='ARTIFACT_COPY_NOT_RENDERING_PROOF'}
   }finally{$fontHasher.Dispose();$fontStream.Dispose()}
  }
   if($multiModuleProfile){
    $runArgs=@('run','--detach','--rm','--name','aiui-workspace-20261008','--memory','2G','--cpus','1','--gpus','all',
     '--env',('MAKEPAD_HOME='+$moduleShellMakepadHome),'--env',('TOOLKIT_MODULE_PROJECT_ID='+$moduleShellProjectId),
     '--env',('TOOLKIT_NATIVE_LATE_PROBE='+$moduleShellLateProbe),
     '--label',('aiui.toolkit.owner='+$Owner),'--label',('aiui.toolkit.nonce='+$nonce),$expectedImage,'sleep','1800')
   }else{
    $runArgs=@('run','--detach','--rm','--name','aiui-workspace-20261008','--memory','1G','--cpus','1','--gpus','all','--label',('aiui.toolkit.owner='+$Owner),'--label',('aiui.toolkit.nonce='+$nonce),$expectedImage,'sleep','1800')
   }
 }else{
  & $capture -Label stage-linux-fixture -Executable 'C:\Windows\System32\wsl.exe' -TimeoutSeconds 30 -OutputDirectory $out -CommandArgs @('-d','Ubuntu','--','cp','/opt/makepad-operator/.cache/makepad-wslg-isolated-target/debug/ai-workspace-fixture',('/mnt/c/'+$out.Replace('\','/').Substring(3)+'/ai-workspace-fixture')) | Out-Null
  $staged=Get-Content (Join-Path $out 'stage-linux-fixture.json') -Raw|ConvertFrom-Json
  if($staged.exit_code -ne 0 -or $staged.timed_out){throw 'Fixture staging failed'}
  $runArgs=@('run','--detach','--rm','--name','aiui-workspace-20261008','--memory','1G','--cpus','1','--gpus','all','aiui-makepad-runtime:20261006','sleep','1800')
 }
 & $capture -Label container-start -Executable $wslc -TimeoutSeconds 60 -OutputDirectory $out -CommandArgs $runArgs | Out-Null
 $launch=Get-Content (Join-Path $out 'container-start.json') -Raw|ConvertFrom-Json
 if($launch.exit_code -ne 0 -or $launch.timed_out -or -not $launch.output_drained){throw 'Container start failed'}
 $id=$launch.stdout.Trim()
 if($id -cnotmatch '^[a-f0-9]{64}$'){throw 'Container identity invalid'}
 if($remoteProfile){
  $createdId=Get-RemoteCreatedContainerId -Creator $launch -Executable $wslc -ExpectedArgs $runArgs
  if(-not $createdId){throw 'REMOTE_CREATOR_PROOF_INVALID'}
 }
 & $capture -Label container-inspect -Executable $wslc -TimeoutSeconds 30 -OutputDirectory $out -CommandArgs @('inspect',$id) | Out-Null
 $inspected=Get-Content (Join-Path $out 'container-inspect.json') -Raw|ConvertFrom-Json
 if($inspected.exit_code -ne 0 -or $inspected.timed_out -or -not $inspected.output_drained){throw 'Container inspection failed'}
 $metadataItems=@($inspected.stdout|ConvertFrom-Json)
 if($metadataItems.Count -ne 1){throw 'Container inspection identity ambiguous'}
 $metadata=$metadataItems[0]
  $expectedContainerMemory=if($multiModuleProfile){2GB}else{1GB}
  if($metadata.Id -cne $id -or $metadata.Name -cne '/aiui-workspace-20261008' -or $metadata.HostConfig.Memory -ne $expectedContainerMemory -or $metadata.HostConfig.NanoCpus -ne 1000000000 -or $metadata.Image -cne $expectedImage -or $metadata.State.Running -ne $true){throw 'Actual container identity/resource limit or trusted image mismatch'}
  if($multiModuleProfile){Assert-ModuleShellContainerEnvironment $metadata.Config}
 if($remoteProfile){
  foreach($labels in @($metadata.Config.Labels,$metadata.Labels)){
   if($null -eq $labels -or $labels.'aiui.toolkit.owner' -cne $Owner -or $labels.'aiui.toolkit.nonce' -cne $nonce){throw 'REMOTE_CREATOR_LABEL_MISMATCH'}
  }
  # JsonDocument preserves the native nanosecond strings; context wall time is
  # NOT a replacement for inspect.Created / inspect.State.StartedAt.
  $nativeJson=[System.Text.Json.JsonDocument]::Parse([string]$inspected.stdout)
  try{
   $containerCreated=$nativeJson.RootElement[0].GetProperty('Created').GetString()
   $containerStartedAt=$nativeJson.RootElement[0].GetProperty('State').GetProperty('StartedAt').GetString()
  }finally{$nativeJson.Dispose()}
  if([string]::IsNullOrEmpty($containerCreated) -or [string]::IsNullOrEmpty($containerStartedAt)){throw 'REMOTE_CREATOR_TIME_MISSING'}
 }
 $ownedId=$id # Only the returned, successfully inspected owned incarnation.
 $context=[ordered]@{container_id=$id;container_name='aiui-workspace-20261008';session_inventory=$sessions;owns_vm=$false;owns_container=$true;connected_default_session=$true;image=$metadata.Image;memory_max=$metadata.HostConfig.Memory;cpus=1;gpu_adapter=if($gpu.vendor -eq 'nvidia'){'NVIDIA'}else{'AUTO'};gpu_profile=$gpu.profile;gpu_config_sha256=$gpu.config_sha256;gpu_policy=$gpu.mode;source_revision='105158e08c89d47f57af4621420ed68eb3a147ce';fixture_sha256=(Get-FileHash (Join-Path $out 'ai-workspace-fixture')).Hash;created_utc=[DateTime]::UtcNow.ToString('o');slots=@{};resumable=$false}
 if($remoteProfile){
  $context.runtime_profile='makepad_remote71';$context.source_revision=$remoteSourceRevision
  $context.exclusive_owner=$Owner;$context.exclusive_nonce=$nonce
  $context.container_created=$containerCreated;$context.container_started_at=$containerStartedAt
 }
  if($multiModuleProfile){
   $context.wslc_profile='wslc_multi_module';$context.memory_max=2147483648
   $context.module_shell_profile_kind=$moduleShellApproval.profile.profile_kind
   $context.module_shell_source_manifest_sha256=$moduleShellApproval.profile.module_shell.source_manifest_sha256
   $context.module_shell_launch_settings_receipt='module-shell-launch-settings.json'
   $context.module_shell_launch_settings_sha256=$moduleShellLaunchSettingsSha256
   $context.module_shell_makepad_home=$moduleShellMakepadHome
   $context.module_shell_project_id=$moduleShellProjectId
   $context.module_shell_native_late_probe=$moduleShellLateProbe
   $context.module_instances=$moduleShellApproval.profile.module_instances
   $context.module_shell_build_receipt=$moduleShellApproval.build_receipt
   $context.module_shell_native_build_receipt=$moduleShellApproval.native_build_receipt
   $context.module_shell_source_manifest=$moduleShellApproval.source_manifest
   $context.module_shell_artifact_id=$moduleShellApproval.artifact.artifact_id
   $context.module_shell_artifact_path=$moduleShellApproval.artifact.path
   $context.module_shell_artifact_sha256=$moduleShellApproval.artifact.sha256
   $context.module_shell_artifact_bytes=$moduleShellApproval.artifact.bytes
   $context.module_shell_preparation_sha256=$moduleShellApprovalSha256
   $context.host_admission_receipt='module-shell-host-admission.json'
  }
 Write-BootstrapJson 'context.json' $context
 if(-not $multiModuleProfile){
  if((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory -lt 1MB){throw 'BLOCKED_ENVIRONMENT: RAM pressure after container start'}
 }
 [void][IO.Directory]::CreateDirectory((Join-Path $out 'sessions'))
 if($remoteProfile){
   if($multiModuleProfile){
    & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source (Join-Path $out 'ai-workspace-fixture') -Artifact fixture -OutputDirectory $out -ContainerId $ownedId `
     -ModuleShellBuildManifest $ModuleShellBuildManifest -ModuleShellBuildManifestSha256 $ModuleShellBuildManifestSha256 -ApprovedModuleShellElf $ApprovedModuleShellElf | Out-Null
   }else{
    & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source (Join-Path $out 'ai-workspace-fixture') -Artifact fixture -OutputDirectory $out -ContainerId $ownedId | Out-Null
   }
  if($remoteProfile -and $RemoteFixture -in @('focus_trace71','module_shell71')){
   $fontEvidencePrefix=if($multiModuleProfile){'module-shell-font'}else{'focus-font'}
   if((Get-Item -LiteralPath $stagedFonts).Length -ne $fontContract.archive_bytes -or
    (Get-FileHash -LiteralPath $stagedFonts -Algorithm SHA256).Hash -cne $fontContract.archive_sha256){throw 'REMOTE_FOCUS_FONT_STAGE_DRIFT'}
   if($multiModuleProfile){
    & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source $stagedFonts -Artifact launcher -OutputDirectory $out -ContainerId $ownedId `
     -ModuleShellBuildManifest $ModuleShellBuildManifest -ModuleShellBuildManifestSha256 $ModuleShellBuildManifestSha256 -ApprovedModuleShellElf $ApprovedModuleShellElf | Out-Null
   }else{
    & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source $stagedFonts -Artifact launcher -OutputDirectory $out -ContainerId $ownedId | Out-Null
   }
   $fontUpload=Get-Content -LiteralPath (Join-Path $out 'launcher-upload.json') -Raw|ConvertFrom-Json
   if($fontUpload.container_id -cne $ownedId -or $fontUpload.sha256 -cne $fontContract.archive_sha256 -or
    $fontUpload.bytes -ne $fontContract.archive_bytes -or $fontUpload.target -cne '/opt/proof/fixture-launch.sh' -or $fontUpload.exit_code -ne 0){throw 'REMOTE_FOCUS_FONT_UPLOAD_REFUSED'}
   $fontListLabel=$fontEvidencePrefix+'-payload-list'
   & $capture -Label $fontListLabel -Executable $wslc -TimeoutSeconds 30 -OutputDirectory $out -CommandArgs @('exec',$ownedId,'tar','-tf','/opt/proof/fixture-launch.sh') | Out-Null
   $fontListing=Get-Content -LiteralPath (Join-Path $out ($fontListLabel+'.json')) -Raw|ConvertFrom-Json
   Assert-RemoteFocusFontListing $fontListing $fontContract
   $fontExtractLabel=$fontEvidencePrefix+'-payload-extract'
   & $capture -Label $fontExtractLabel -Executable $wslc -TimeoutSeconds 30 -OutputDirectory $out -CommandArgs @('exec',$ownedId,'sh','-ec','mkdir -p /opt/makepad-operator/.cache/makepad-dev-pilot-20261015/source-71c9ddc/widgets/resources; tar -xf /opt/proof/fixture-launch.sh -C /opt/makepad-operator/.cache/makepad-dev-pilot-20261015/source-71c9ddc/widgets/resources') | Out-Null
   $fontExtract=Get-Content -LiteralPath (Join-Path $out ($fontExtractLabel+'.json')) -Raw|ConvertFrom-Json
   if($fontExtract.exit_code -ne 0 -or $fontExtract.timed_out -or -not $fontExtract.output_drained -or $fontExtract.stderr -cne ''){throw 'REMOTE_FOCUS_FONT_EXTRACT_FAILED'}
   foreach($font in $fontContract.files){
    $fontLabel=$fontEvidencePrefix+'-'+$font.name.Replace('.','_')
    $fontTarget=$fontContract.target_directory+'/'+$font.name
    & $capture -Label $fontLabel -Executable $wslc -TimeoutSeconds 30 -OutputDirectory $out -CommandArgs @('exec',$ownedId,'sha256sum',$fontTarget) | Out-Null
    $fontVerified=Get-Content -LiteralPath (Join-Path $out ($fontLabel+'.json')) -Raw|ConvertFrom-Json
    if($fontVerified.exit_code -ne 0 -or $fontVerified.timed_out -or -not $fontVerified.output_drained -or $fontVerified.stderr -cne '' -or
     $fontVerified.stdout -cnotmatch ('\A(?i:'+$font.sha256+')[ \t]+'+[regex]::Escape($fontTarget)+'(?:\r?\n)?\z')){throw 'REMOTE_FOCUS_FONT_GUEST_HASH_REFUSED'}
   }
   Write-BootstrapJson ($fontEvidencePrefix+'s-verified.json') @{container_id=$ownedId;manifest_source=$fontManifestPath;
    archive_source=$fontArchivePath;contract=$fontContract;scope='RESOURCE_DELIVERY_NOT_RENDERING_PROOF'}
  }
 }else{
  & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source (Join-Path $out 'ai-workspace-fixture') -Artifact fixture -OutputDirectory $out | Out-Null
  & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source (Join-Path $out 'ai-workspace-xinput') -Artifact input -OutputDirectory $out | Out-Null
  & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source (Join-Path $PSScriptRoot '../../reports/evidence/makepad-wslc-multi-session-2026-10-06/aiui-xinput') -Artifact inventory -OutputDirectory $out | Out-Null
  & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source (Join-Path $PSScriptRoot 'fixture-launch.sh') -Artifact launcher -OutputDirectory $out | Out-Null
  & (Join-Path $PSScriptRoot 'upload-artifact.ps1') -Source (Join-Path $PSScriptRoot 'partial-stop.sh') -Artifact partial-stop -OutputDirectory $out | Out-Null
 }
 $context|ConvertTo-Json -Depth 6
}catch{
 $bootstrapError=$_
 $stopId=$ownedId
 if($remoteProfile -and -not $stopId){$stopId=$createdId}
 $failure=@{utc=[DateTime]::UtcNow.ToString('o');error=$bootstrapError.Exception.Message;returned_container_id=$id;verified_owned_container_id=$ownedId;owns_vm=$false;cleanup_not_inferred=$true}
 if($remoteProfile){
  $failure.creator_proven_container_id=$createdId
  $failure.inspect_approved=[bool]$ownedId
  $failure.cleanup_stop_container_id=$stopId
  $failure.cleanup_stop_authority=if($ownedId){'INSPECT_APPROVED'}elseif($createdId){'SUCCESSFUL_FIXED_CREATOR'}else{'UNPROVEN_NO_STOP_AUTHORITY'}
 }
 try{Write-BootstrapJson 'bootstrap-failure.json' $failure}catch{Write-Warning 'Bootstrap failure receipt could not be written; original receipts retained'}
 if($stopId){
  try{& $capture -Label failed-bootstrap-container-stop -Executable $wslc -TimeoutSeconds 30 -OutputDirectory $out -CommandArgs @('stop',$stopId) | Out-Null}catch{Write-Warning 'Owned CID stop unconfirmed; inspect retained failure/stop receipts'}
 }
 throw $bootstrapError
}
