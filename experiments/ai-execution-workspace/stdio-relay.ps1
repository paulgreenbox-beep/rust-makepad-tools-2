param([ValidateSet('aiui-workspace-20261008')][string]$Container = 'aiui-workspace-20261008', [ValidateRange(10,720)][int]$Seconds = 360, [ValidateSet(66,67,68,69)][int]$DisplayNumber = 66, [string]$Label = 'workspace-relay', [Parameter(Mandatory=$true)][string]$OutputDirectory, [string]$ProcessNonce, [switch]$ModuleShellBudget, [string]$ContainerId)
$ErrorActionPreference = 'Stop'
$selectedContainer = $Container
if ($PSBoundParameters.ContainsKey('ProcessNonce') -and $ProcessNonce -cnotmatch '^[0-9a-f]{32}$') { throw 'PROCESS_NONCE_INVALID' }
if ($PSBoundParameters.ContainsKey('ContainerId')) {
    if ($PSBoundParameters.ContainsKey('Container')) { throw 'CONTAINER_ARGUMENTS_CONFLICT' }
    if ($ContainerId -cnotmatch '^[0-9a-f]{64}$') { throw 'CONTAINER_ID_INVALID' }
    $selectedContainer = $ContainerId
}
function Assert-RelayRuntimeBudget([int]$Seconds,[bool]$ModuleShell,$Context,[string]$Id){
 if(-not $ModuleShell){if($Seconds -gt 600){throw 'RELAY_LEGACY_BUDGET_REFUSED'};return}
 if($Seconds -ne 720 -or $Id -cnotmatch '^[a-f0-9]{64}$' -or $Context.container_id -cne $Id -or
  $Context.runtime_profile -cne 'makepad_remote71' -or $Context.wslc_profile -cne 'wslc_multi_module' -or
  $Context.module_shell_profile_kind -cne 'ModuleShell' -or
  $Context.module_shell_source_manifest_sha256 -cne '91F63101687B7BFB778391AB780BCF5AF1B8697D3DA81B5E08E70FFF39C32E42' -or
  $Context.fixture_sha256 -cne 'F7B286EF5A851028BA631A690ED0CE2FC3D4F71F91E0097BA28A7F71DDC93489' -or
  $Context.owns_container -isnot [bool] -or $Context.owns_container -ne $true -or
  $Context.owns_vm -isnot [bool] -or $Context.owns_vm -ne $false -or
  $Context.memory_max -ne 2147483648 -or
  -not ($Context.cpus -is [int] -or $Context.cpus -is [long]) -or $Context.cpus -ne 1 -or $Context.module_instances -ne 2){
  throw 'RELAY_MODULE_SHELL_BUDGET_REFUSED'
 }
}
$budgetContext=$null
if($ModuleShellBudget){$budgetContext=Get-Content -LiteralPath (Join-Path $OutputDirectory 'context.json') -Raw|ConvertFrom-Json}
Assert-RelayRuntimeBudget $Seconds $ModuleShellBudget.IsPresent $budgetContext $ContainerId
function Start-Endpoint([string]$File, [string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $File
    foreach ($value in $Arguments) { $start.ArgumentList.Add($value) }
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    [void]$process.Start()
    return $process
}
$source = $null
$sink = $null
$timer = [Diagnostics.Stopwatch]::StartNew()
$record = [ordered]@{ label=$Label; started_utc=[DateTime]::UtcNow.ToString('o'); container=$selectedContainer; transport='binary anonymous stdio pipes, no TTY'; source_endpoint='Ubuntu:/tmp/.X11-unix/X0'; container_endpoint=('/tmp/.X11-unix/X'+$DisplayNumber); socket_mode='0600'; max_clients=1; tcp_listener_count=0; credentials_transferred=$false; timeout_seconds=$Seconds }
try {
    $source = Start-Endpoint 'C:\Windows\System32\wsl.exe' @('-d','Ubuntu','--','timeout','--signal=TERM','--kill-after=2s',($Seconds.ToString()+'s'),'socat','-d','-d','STDIO','UNIX-CONNECT:/tmp/.X11-unix/X0')
    # The container listener alone is not readiness. On a cold Ubuntu launch,
    # its X11 client can time out before this upstream connection even exists.
    $sourcePrefix=[Text.StringBuilder]::new();$upstreamReady=$false
    $lineTask=$source.StandardError.ReadLineAsync()
    while($timer.Elapsed.TotalSeconds -lt 15){
        if($lineTask.IsCompleted){
            $line=$lineTask.GetAwaiter().GetResult()
            if($null -eq $line){break}
            [void]$sourcePrefix.AppendLine($line)
            if($line -match 'successfully connected'){$upstreamReady=$true;break}
            $lineTask=$source.StandardError.ReadLineAsync()
        }
        if($source.HasExited){break}
        Start-Sleep -Milliseconds 25
    }
    if(-not $upstreamReady){throw 'UPSTREAM_X11_NOT_READY'}
    $sinkArgs=@('exec','-i',$selectedContainer)
    # Trusted internal process ownership token, never a public TestJob env map.
    if ($ProcessNonce) { $sinkArgs+=@('env',('AIUI_REMOTE_LAUNCH_NONCE='+$ProcessNonce)) }
    $sinkArgs+=@('timeout','--signal=TERM','--kill-after=2s',($Seconds.ToString()+'s'),'socat','-d','-d',('UNIX-LISTEN:/tmp/.X11-unix/X'+$DisplayNumber+',mode=0600,unlink-close'),'STDIO')
    $sink = Start-Endpoint 'C:\Program Files\WSL\wslc.exe' $sinkArgs
    $record.source_host_pid = $source.Id
    $record.container_exec_host_pid = $sink.Id
    $sourceErrors = $source.StandardError.ReadToEndAsync()
    $sinkErrors = $sink.StandardError.ReadToEndAsync()
    [IO.File]::WriteAllText((Join-Path $OutputDirectory ($Label+'.ready.json')),([ordered]@{upstream_connected=$true;source_host_pid=$source.Id;container_exec_host_pid=$sink.Id;container_endpoint=$record.container_endpoint}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    $toSource = $sink.StandardOutput.BaseStream.CopyToAsync($source.StandardInput.BaseStream)
    $toSink = $source.StandardOutput.BaseStream.CopyToAsync($sink.StandardInput.BaseStream)
    [Console]::WriteLine(('STDIO_RELAY_STARTED source_pid={0} sink_pid={1}' -f $source.Id,$sink.Id))
    $sourceInputClosed = $false
    $sinkInputClosed = $false
    while ($timer.Elapsed.TotalSeconds -lt ($Seconds + 3)) {
        if ($toSource.IsCompleted -and -not $sourceInputClosed) { $source.StandardInput.Close(); $sourceInputClosed = $true }
        if ($toSink.IsCompleted -and -not $sinkInputClosed) { $sink.StandardInput.Close(); $sinkInputClosed = $true }
        if ($source.HasExited -and $sink.HasExited) { break }
        Start-Sleep -Milliseconds 100
    }
    $record.source_exited_before_host_deadline = $source.HasExited
    $record.container_exec_exited_before_host_deadline = $sink.HasExited
    $record.source_pump_status = $toSink.Status.ToString()
    $record.container_pump_status = $toSource.Status.ToString()
} finally {
    foreach ($process in @($source,$sink)) {
        if ($null -ne $process -and -not $process.HasExited) { $process.Kill($true); if(-not $process.WaitForExit(3000)){throw 'RELAY_ENDPOINT_CLEANUP_UNCONFIRMED'} }
    }
    if ($null -ne $source) { $record.source_exit_code=$source.ExitCode; $record.source_stderr=$sourcePrefix.ToString()+$(if($sourceErrors){$sourceErrors.GetAwaiter().GetResult()}else{''}); $source.Dispose() }
    if ($null -ne $sink) { $record.container_exec_exit_code=$sink.ExitCode; $record.container_stderr=$(if($sinkErrors){$sinkErrors.GetAwaiter().GetResult()}else{''}); $sink.Dispose() }
    $record.duration_ms=$timer.ElapsedMilliseconds
    $json=$record | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText((Join-Path $OutputDirectory ($Label + '.json')), $json, [Text.UTF8Encoding]::new($false))
    [Console]::WriteLine($json)
}
