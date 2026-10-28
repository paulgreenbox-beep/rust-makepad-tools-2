param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../../reports/evidence/ai-execution-workspace-2026-10-08'), [ValidateSet('inspection','build','warm-build','runtime')][string]$Purpose='inspection')
$ErrorActionPreference='Stop'

# Pure policy/decision functions are also exercised by the existing isolated
# PowerShell contract-test style; no mock can authorize the real entry point.
function Get-ToolkitRamMinimumKiB([string]$Purpose,$Policy) {
 if($Purpose -notin @('inspection','build','warm-build','runtime')){throw 'RESOURCE_PURPOSE_INVALID'}
 $minimum=$Policy.resource_guards.min_available_physical_ram_mib
 if($minimum -isnot [int] -and $minimum -isnot [long] -and $minimum -isnot [uint32] -and $minimum -isnot [uint64]){throw 'RESOURCE_POLICY_INVALID'}
 if($minimum -le 0 -or [decimal]$minimum -gt ([decimal][long]::MaxValue/1048576) -or $Policy.resource_guards.wslc_min_available_ram_mib -ne $minimum){throw 'RESOURCE_POLICY_INVALID'}
 if($Purpose -eq 'inspection'){return [long]0}
 return [long]$minimum*1024
}
function Get-ToolkitActiveCompilers($Processes) {
 @($Processes | Where-Object {
  if($_.Name -ieq 'rustc.exe'){return $true}
  if($_.Name -ine 'cargo.exe'){return $false}
  # Only a known legacy MCP `cargo run` parent is not itself a build. A cargo
  # build/test/check --bin MCP must NOT bypass the compiler guard.
  return -not ($_.CommandLine -match '(?i)(?:^|\s)run(?:\s|$)' -and
   $_.CommandLine -match '--bin\s+toolkit-windows-gui-mcp(?:\s|$)' -and
   $_.CommandLine -notmatch '(?i)(?:^|\s)(build|test|check|bench|rustc)(?:\s|$)')
 })
}
function Test-ToolkitResourceAdmission([string]$Purpose,$Policy,$FreeKiB,$TotalKiB,$Compilers,$MeasuredAt,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow) {
 $required=Get-ToolkitRamMinimumKiB $Purpose $Policy
 $blockers=[Collections.Generic.List[string]]::new()
 $valid=$true
 foreach($number in @($FreeKiB,$TotalKiB)){
  if(($number -isnot [int] -and $number -isnot [long] -and $number -isnot [uint32] -and $number -isnot [uint64]) -or
   $number -lt 0 -or [decimal]$number -gt ([decimal][long]::MaxValue/1024)){$valid=$false}
 }
 if(-not $valid -or $TotalKiB -le 0 -or $FreeKiB -gt $TotalKiB){$blockers.Add('invalid_memory_measurement');$valid=$false}
 $at=[DateTimeOffset]::MinValue
 if($MeasuredAt -isnot [string] -or -not [DateTimeOffset]::TryParse($MeasuredAt,[ref]$at)){$blockers.Add('invalid_measurement_timestamp')}
 else{
  $age=($Now-$at).TotalSeconds
  $limit=$Policy.resource_guards.preflight_max_age_seconds
  if($limit -isnot [long] -and $limit -isnot [int]){throw 'RESOURCE_POLICY_INVALID'}
  if($limit -le 0 -or $limit -gt 60){throw 'RESOURCE_POLICY_INVALID'}
  if($age -lt 0 -or $age -gt $limit){$blockers.Add('stale_resource_measurement')}
 }
 if($Compilers -isnot [array]){$blockers.Add('invalid_compiler_observation')}
 elseif($Compilers.Count -gt 0){$blockers.Add('active_rust_compiler_or_build')}
 if($valid -and $FreeKiB -lt $required){$blockers.Add('insufficient_available_ram')}
 [ordered]@{status=if($blockers.Count -eq 0){'ADMITTED'}else{'BLOCKED_ENVIRONMENT'};
  ram_guard_status=if($valid -and $FreeKiB -ge $required){'RAM_GUARD_ADMITTED'}else{'BLOCKED_RESOURCE'};
  required_free_kib=$required;blockers=@($blockers)}
}
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$out=[IO.Path]::GetFullPath($OutputDirectory)
$evidence=[IO.Path]::GetFullPath((Join-Path $root 'reports/evidence'))+[IO.Path]::DirectorySeparatorChar
if(-not $out.StartsWith($evidence,[StringComparison]::OrdinalIgnoreCase)){throw 'Evidence must stay under the local ignored reports/evidence root'}
$policyPath=Join-Path $root 'verification-economy/core/global-policy.json'
$policy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
$os=Get-CimInstance Win32_OperatingSystem
$measuredAt=[DateTimeOffset]::UtcNow.ToString('o')
$processes=@(Get-CimInstance Win32_Process | Where-Object {$_.Name -match '^(rustc|cargo|vmmem.*|msrdc|wslc|socat|.*ocr.*)\.exe$'} | Select-Object ProcessId,Name,CommandLine)
$compilers=@(Get-ToolkitActiveCompilers $processes)
# Existing long-lived Cargo parents of the installed MCP server are not a
# concurrent build. Any rustc process still blocks admission independently.
# Conservative local admission, not an assertion about WSLC VM-wide limits.
# All admitted heavy purposes read the same 2 GiB source-of-truth policy.
$decision=Test-ToolkitResourceAdmission $Purpose $policy $os.FreePhysicalMemory $os.TotalVisibleMemorySize $compilers $measuredAt
$admitted=$decision.status -eq 'ADMITTED'
$record=[ordered]@{utc=$measuredAt;purpose=$Purpose;status=$decision.status;ram_guard_status=$decision.ram_guard_status;blockers=$decision.blockers;free_physical_kib=$os.FreePhysicalMemory;total_physical_kib=$os.TotalVisibleMemorySize;required_free_kib=$decision.required_free_kib;resource_policy_sha256=(Get-FileHash -LiteralPath $policyPath).Hash;active_rust_compilers=$compilers;observed_processes=$processes;wslconfig_sha256=(Get-FileHash -LiteralPath (Join-Path $env:USERPROFILE '.wslconfig')).Hash;git_head=(& git -C $root rev-parse HEAD);git_status=@(& git -C $root status --short);vm_wide_limit_claim=$false;foreign_processes_changed=$false}
[void][IO.Directory]::CreateDirectory($out)
$json=$record | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $out ($Purpose+'-admission.json')),$json,[Text.UTF8Encoding]::new($false))
$json
if(-not $admitted){exit 2}
