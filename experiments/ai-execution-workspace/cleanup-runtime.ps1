param([string]$OutputDirectory=(Join-Path $PSScriptRoot '../../reports/evidence/ai-execution-workspace-2026-10-08'),[string]$OwnedBindingsBase64)
$ErrorActionPreference='Stop'
$out=[IO.Path]::GetFullPath($OutputDirectory)
$allowed=(Resolve-Path (Join-Path $PSScriptRoot '../../reports/evidence')).Path+'\'
if(-not $out.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Evidence scope refused'}
$context=Get-Content (Join-Path $out 'context.json') -Raw|ConvertFrom-Json
if($context.container_id -notmatch '^[a-f0-9]{64}$' -or $context.container_name -ne 'aiui-workspace-20261008' -or $context.owns_container -ne $true){throw 'Owned container identity missing'}
$wslc='C:\Program Files\WSL\wslc.exe'
$capture=Join-Path $PSScriptRoot 'capture-process.ps1'
function Assert-CleanupContainerIdentity($Context,$Creator,$Actual){
 if($null -eq $Creator -or $null -eq $Actual -or $Creator.stdout -isnot [string] -or $Creator.args -isnot [array] -or
  $Context.container_id -cnotmatch '^[a-f0-9]{64}$' -or $Context.image -cnotmatch '^sha256:[a-f0-9]{64}$' -or
  [string]::IsNullOrWhiteSpace([string]$Context.container_created) -or [string]::IsNullOrWhiteSpace([string]$Context.container_started_at) -or
  $Context.exclusive_nonce -cnotmatch '^[a-f0-9]{32}$' -or
  [string]::IsNullOrWhiteSpace($Context.exclusive_owner) -or $Context.owns_vm -ne $false -or
  $Creator.label -cne 'container-start' -or $Creator.executable -cne 'C:\Program Files\WSL\wslc.exe' -or
  $Creator.exit_code -ne 0 -or $Creator.timed_out -ne $false -or $Creator.output_drained -ne $true -or
  $Creator.owned_tree_termination_requested -ne $false -or
  $Creator.stdout.Trim() -cne $Context.container_id -or $Creator.args[0] -cne 'run' -or
  @($Creator.args|Where-Object {$_ -ceq ('aiui.toolkit.owner='+$Context.exclusive_owner)}).Count -ne 1 -or
  @($Creator.args|Where-Object {$_ -ceq ('aiui.toolkit.nonce='+$Context.exclusive_nonce)}).Count -ne 1 -or
  $Actual.Id -cne $Context.container_id -or $Actual.Image -cne $Context.image -or
  $Actual.Created -cne $Context.container_created -or $Actual.State.StartedAt -cne $Context.container_started_at -or
  $Actual.Config.Labels.'aiui.toolkit.owner' -cne $Context.exclusive_owner -or
  $Actual.Config.Labels.'aiui.toolkit.nonce' -cne $Context.exclusive_nonce -or
  @($Actual.Mounts).Count -ne 0){throw 'CLEANUP_IDENTITY_NOT_VERIFIED'}
}
function Test-CleanupContainerAbsent([string]$Cid){
 $quiet=& $wslc list --all --no-trunc --quiet --filter ('id='+$Cid) 2>$null
 if($LASTEXITCODE -ne 0){throw 'CLEANUP_IDENTITY_NOT_VERIFIED'}
 $value=($quiet -join "`n").Trim()
 if($value -eq ''){return $true}
 if($value -cne $Cid){throw 'CLEANUP_IDENTITY_NOT_VERIFIED'}
 return $false
}
$bindings=@()
if(-not $PSBoundParameters.ContainsKey('OwnedBindingsBase64')){
 $bindings=@(Get-ChildItem (Join-Path $out 'sessions') -Filter binding.json -Recurse -File | ForEach-Object {Get-Content $_.FullName -Raw|ConvertFrom-Json})
}
if($PSBoundParameters.ContainsKey('OwnedBindingsBase64')){
 # Fixed owner passes its retained native bindings even if a new sidecar write
 # failed. No PID discovery, filename override or public Script authority here.
 if($OwnedBindingsBase64.Length -gt 4096 -or $OwnedBindingsBase64 -cnotmatch '^[A-Za-z0-9+/]+={0,2}$'){throw 'OWNED_BINDINGS_ENCODING_REFUSED'}
 $retained=[Text.UTF8Encoding]::new($false,$true).GetString([Convert]::FromBase64String($OwnedBindingsBase64))|ConvertFrom-Json
 foreach($property in $retained.PSObject.Properties){
  if($property.Name -notin @('runtime','relay')){throw 'OWNED_BINDINGS_SCHEMA_REFUSED'}
  $row=$property.Value
  if(@($row.PSObject.Properties.Name).Count -ne 2 -or $null -eq $row.pid -or $null -eq $row.start_ticks -or
   [string]$row.pid -cnotmatch '^[1-9][0-9]{0,9}$' -or [string]$row.start_ticks -cnotmatch '^[1-9][0-9]{0,18}$'){throw 'OWNED_BINDINGS_SCHEMA_REFUSED'}
 }
 $bindings+=@($retained)
}
$before=& $wslc inspect $context.container_id 2>$null
if($LASTEXITCODE -eq 0){
 $actual=($before|ConvertFrom-Json)[0]
 $creator=Get-Content -LiteralPath (Join-Path $out 'container-start.json') -Raw|ConvertFrom-Json
 Assert-CleanupContainerIdentity $context $creator $actual
 & $capture -Label final-container-memory -Executable $wslc -TimeoutSeconds 10 -OutputDirectory $out -CommandArgs @('exec',$context.container_id,'sh','-c','cat /sys/fs/cgroup/memory.current; cat /sys/fs/cgroup/memory.peak; cat /sys/fs/cgroup/memory.events; ps -eo pid,comm,args') | Out-Null
 if($actual.State.Running){
  & $capture -Label final-container-stop -Executable $wslc -TimeoutSeconds 30 -OutputDirectory $out -CommandArgs @('stop',$context.container_id) | Out-Null
  $stopped=Get-Content (Join-Path $out 'final-container-stop.json') -Raw|ConvertFrom-Json
  if($stopped.exit_code -ne 0 -or $stopped.timed_out){throw 'Owned container cleanup failed'}
 }
 if(-not (Test-CleanupContainerAbsent $context.container_id)){
  $remainingActual=((& $wslc inspect $context.container_id)|ConvertFrom-Json)[0]
  if($LASTEXITCODE -ne 0 -or $remainingActual.State.Running){throw 'CLEANUP_IDENTITY_NOT_VERIFIED'}
  Assert-CleanupContainerIdentity $context $creator $remainingActual
  & $capture -Label final-stopped-container-remove -Executable $wslc -TimeoutSeconds 15 -OutputDirectory $out -CommandArgs @('remove',$context.container_id) | Out-Null
  $removed=Get-Content -LiteralPath (Join-Path $out 'final-stopped-container-remove.json') -Raw|ConvertFrom-Json
  if($removed.exit_code -ne 0 -or $removed.timed_out){throw 'Owned stopped container removal unconfirmed'}
 }
}
elseif(-not (Test-CleanupContainerAbsent $context.container_id)){throw 'CLEANUP_IDENTITY_NOT_VERIFIED'}
# A default VM connection is never ownership of the VM. Do not terminate it.
$hostCleanup=@()
foreach($binding in $bindings){
 foreach($kind in @('runtime','relay')){
  $owned=$binding.$kind
  if(-not $owned){continue}
  $p=Get-Process -Id $owned.pid -ErrorAction SilentlyContinue
  if($p -and $p.StartTime.ToUniversalTime().Ticks -eq $owned.start_ticks){
   if(-not $p.WaitForExit(5000)){$p.Kill($true);[void]$p.WaitForExit(3000)}
   $hostCleanup+=@{kind=$kind;pid=$owned.pid;creation_identity_matched=$true;exited=$p.HasExited};$p.Dispose()
  }else{$hostCleanup+=@{kind=$kind;pid=$owned.pid;creation_identity_matched=($null -eq $p);exited=($null -eq $p)}}
 }
}
$containerAbsent=Test-CleanupContainerAbsent $context.container_id
& (Join-Path $PSScriptRoot 'native-inventory.ps1') -Label final-native-inventory -OutputDirectory $out | Out-Null
$windows=Get-Content (Join-Path $out 'final-native-inventory.json') -Raw|ConvertFrom-Json
$ownedHandles=@($bindings|Where-Object identity|ForEach-Object {'0x{0:X}' -f [long]$_.identity.hwnd})
$stale=@($windows.windows|Where-Object {$_.hwnd -in $ownedHandles})
$record=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');container_id=$context.container_id;owned_container_absent=$containerAbsent;owned_host_process_cleanup=$hostCleanup;stale_owned_windows=$stale;connected_vm_preserved=$true;owns_vm=$false;vm_leak_count=$null;normal_application_exit_requires_per_session_runtime_evidence=$true;physical_input_injected=$false;wslconfig_sha256=(Get-FileHash (Join-Path $env:USERPROFILE '.wslconfig')).Hash;status=if($containerAbsent -and $stale.Count -eq 0 -and @($hostCleanup|Where-Object {-not $_.exited}).Count -eq 0){'OWNED_RESOURCES_CLEANED'}else{'CLEANUP_UNCONFIRMED'}}
if($context.module_shell_profile_kind -ceq 'ModuleShell'){
 $record.host_ram_mode='USER_WAIVED';$record.available_memory_query_performed=$false
}else{
 $record.free_physical_kib=(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory
}
[IO.File]::WriteAllText((Join-Path $out 'cleanup.json'),($record|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
$record|ConvertTo-Json -Depth 8
if($record.status -ne 'OWNED_RESOURCES_CLEANED'){throw 'Cleanup remains unconfirmed'}
