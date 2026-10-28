param(
 [Parameter(Mandatory=$true)][string]$Label,
 [Parameter(Mandatory=$true)][string]$Executable,
 [ValidateRange(1,900)][int]$TimeoutSeconds=90,
 [Parameter(Mandatory=$true)][string]$OutputDirectory,
 [switch]$StreamOutputFiles,
 [ValidateRange(1,33554432)][int]$StdoutLimitBytes=1048576,
 [ValidateRange(1,33554432)][int]$StderrLimitBytes=65536,
 [string[]]$CommandArgs=@()
)
$ErrorActionPreference='Stop'
# Reusable API: ToolkitBoundedOutput.CopyBoundedAsync(Stream, Stream, long, CancellationToken).
function Initialize-ToolkitBoundedOutput {
 if(-not ('ToolkitBoundedOutput' -as [type])){
  $pumpSource=@'
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

public sealed class ToolkitBoundedOutputResult
{
    public long BytesWritten { get; set; }
    public bool Overflow { get; set; }
    public string Fault { get; set; }
}

public static class ToolkitBoundedOutput
{
    private const int BufferBytes = 81920;
    private const int FaultTextLimit = 2048;

    private static string Limit(string value)
    {
        if (value == null || value.Length <= FaultTextLimit) return value;
        return value.Substring(0, FaultTextLimit);
    }

    public static async Task<ToolkitBoundedOutputResult> CopyBoundedAsync(
        Stream input, Stream output, long byteLimit, CancellationToken cancellationToken)
    {
        var result = new ToolkitBoundedOutputResult();
        var buffer = new byte[BufferBytes];
        try
        {
            while (true)
            {
                int count = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                if (count == 0) break;
                long remaining = byteLimit - result.BytesWritten;
                int accepted = (int)Math.Min((long)count, Math.Max(0L, remaining));
                if (accepted > 0)
                {
                    await output.WriteAsync(buffer, 0, accepted, cancellationToken).ConfigureAwait(false);
                    result.BytesWritten += accepted;
                }
                if (count > remaining)
                {
                    result.Overflow = true;
                    break;
                }
            }
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            result.Fault = Limit(exception.ToString());
        }
        return result;
    }
}
'@
  Add-Type -TypeDefinition $pumpSource -Language CSharp -ErrorAction Stop
 }
}
Initialize-ToolkitBoundedOutput

$start=[Diagnostics.ProcessStartInfo]::new()
$start.FileName=(Get-Command $Executable -ErrorAction Stop).Source
$start.UseShellExecute=$false;$start.CreateNoWindow=$true
$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
foreach($override in @('GALLIUM_DRIVER','MESA_D3D12_DEFAULT_ADAPTER_NAME')){[void]$start.Environment.Remove($override)}
foreach($arg in $CommandArgs){[void]$start.ArgumentList.Add($arg)}
$process=[Diagnostics.Process]::new();$process.StartInfo=$start
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$safeLabel=$Label -replace '[^a-zA-Z0-9_-]','_'
$outPath=Join-Path $OutputDirectory ($safeLabel+'.stdout.txt')
$errPath=Join-Path $OutputDirectory ($safeLabel+'.stderr.txt')
if($StreamOutputFiles){
 $stdout=[IO.FileStream]::new($outPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite,81920,[IO.FileOptions]::Asynchronous)
 $stderr=[IO.FileStream]::new($errPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite,81920,[IO.FileOptions]::Asynchronous)
}else{$stdout=[IO.MemoryStream]::new();$stderr=[IO.MemoryStream]::new()}

$cancel=[Threading.CancellationTokenSource]::new()
$began=[DateTime]::UtcNow.ToString('o');$timer=[Diagnostics.Stopwatch]::StartNew()
$ownedPid=0;$timedOut=$false;$terminationRequested=$false;$containmentFault=$null
$stdoutState=[ordered]@{done=$false;result=$null;fault=$null}
$stderrState=[ordered]@{done=$false;result=$null;fault=$null}
$limitText={param([string]$value) if($null -ne $value -and $value.Length -gt 2048){$value.Substring(0,2048)}else{$value}}
$updatePump={
 param($task,$state)
 if(-not $task.IsCompleted -or $state.done){return}
 $state.done=$true
 try{
  $state.result=$task.GetAwaiter().GetResult()
  if($state.result.Fault){$state.fault=& $limitText ([string]$state.result.Fault)}
 }catch{$state.fault=& $limitText $_.Exception.ToString()}
}
try{
 [void]$process.Start();$ownedPid=$process.Id
 $outTask=[ToolkitBoundedOutput]::CopyBoundedAsync($process.StandardOutput.BaseStream,$stdout,$StdoutLimitBytes,$cancel.Token)
 $errTask=[ToolkitBoundedOutput]::CopyBoundedAsync($process.StandardError.BaseStream,$stderr,$StderrLimitBytes,$cancel.Token)
 $deadlineMs=[long]$TimeoutSeconds*1000
 while($true){
  & $updatePump $outTask $stdoutState
  & $updatePump $errTask $stderrState
  $stdoutOverflow=[bool]($stdoutState.result -and $stdoutState.result.Overflow)
  $stderrOverflow=[bool]($stderrState.result -and $stderrState.result.Overflow)
  if($timer.ElapsedMilliseconds -ge $deadlineMs){$timedOut=$true;break}
  if($stdoutOverflow -or $stderrOverflow -or $stdoutState.fault -or $stderrState.fault){break}
  if($process.HasExited -and $stdoutState.done -and $stderrState.done){break}
  $remainingMs=$deadlineMs-$timer.ElapsedMilliseconds
  $pauseMs=[int][Math]::Min([long]20,[long]$remainingMs)
  if($pauseMs -lt 1){$pauseMs=1}
  Start-Sleep -Milliseconds $pauseMs
 }

 $stdoutOverflow=[bool]($stdoutState.result -and $stdoutState.result.Overflow)
 $stderrOverflow=[bool]($stderrState.result -and $stderrState.result.Overflow)
 $needsContainment=$timedOut -or $stdoutOverflow -or $stderrOverflow -or $stdoutState.fault -or $stderrState.fault
 if($needsContainment){
  try{
   if(-not $process.HasExited){$process.Kill($true);$terminationRequested=$true;[void]$process.WaitForExit(3000)}
  }catch{$containmentFault=& $limitText $_.Exception.ToString()}
  $drainTimer=[Diagnostics.Stopwatch]::StartNew()
  while((-not $outTask.IsCompleted -or -not $errTask.IsCompleted) -and $drainTimer.ElapsedMilliseconds -lt 3000){Start-Sleep -Milliseconds 10}
  & $updatePump $outTask $stdoutState
  & $updatePump $errTask $stderrState
 }
 $drained=$outTask.IsCompleted -and $errTask.IsCompleted
 if(-not $drained){$cancel.Cancel()}
 $stdoutOverflow=[bool]($stdoutState.result -and $stdoutState.result.Overflow)
 $stderrOverflow=[bool]($stderrState.result -and $stderrState.result.Overflow)
 $failureReasons=@();$faultParts=@()
 if($timedOut){$failureReasons+='timeout';$faultParts+='PROCESS_TIMEOUT'}
 if($stdoutOverflow){$failureReasons+='stdout_overflow'}
 if($stderrOverflow){$failureReasons+='stderr_overflow'}
 if($stdoutState.fault){$failureReasons+='stdout_fault';$faultParts+=('stdout: '+$stdoutState.fault)}
 if($stderrState.fault){$failureReasons+='stderr_fault';$faultParts+=('stderr: '+$stderrState.fault)}
 if($containmentFault){$failureReasons+='containment_fault';$faultParts+=('containment: '+$containmentFault)}
 if(-not $drained){$failureReasons+='drain_failure';$faultParts+='PROCESS_PIPE_DRAIN_FAILURE'}
 $captureAccepted=$failureReasons.Count -eq 0
 $captureFault=if($faultParts.Count){& $limitText ($faultParts -join '; ')}else{$null}
 $captureFailureReason=if($failureReasons.Count){$failureReasons -join ','}else{$null}

 if($StreamOutputFiles){
  $stdout.Flush();$stderr.Flush();$stdout.Dispose();$stderr.Dispose()
  $outRaw=[IO.File]::ReadAllBytes($outPath);$errRaw=[IO.File]::ReadAllBytes($errPath)
 }else{
  $outRaw=$stdout.ToArray();$errRaw=$stderr.ToArray()
  if(-not $captureAccepted){
   $rawOut=[IO.FileStream]::new($outPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
   try{$rawOut.Write($outRaw,0,$outRaw.Length)}finally{$rawOut.Dispose()}
   $rawErr=[IO.FileStream]::new($errPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
   try{$rawErr.Write($errRaw,0,$errRaw.Length)}finally{$rawErr.Dispose()}
  }
 }
 $decode={param($bytes) if($bytes -contains 0){[Text.Encoding]::Unicode.GetString($bytes).TrimStart([char]0xfeff)}else{[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xfeff)}}
 $out=& $decode $outRaw;$err=& $decode $errRaw
 # Native process timestamps and stopwatch elapsed have different purposes.
 # Never derive a filesystem/UTC end time by adding monotonic elapsed to UTC.
 $nativeStart=$process.StartTime.ToUniversalTime().ToString('o')
 $nativeExit=if($process.HasExited){$process.ExitTime.ToUniversalTime().ToString('o')}else{$null}
 $exitCode=if($process.HasExited){$process.ExitCode}else{$null}
 $record=[ordered]@{
  label=$Label;started_utc=$began;process_started_utc=$nativeStart;process_exited_utc=$nativeExit
  executable=$start.FileName;args=$CommandArgs;owned_pid=$ownedPid;exit_code=$exitCode
  timed_out=$timedOut;output_drained=$drained;duration_ms=$timer.ElapsedMilliseconds
  stdout=$out;stderr=$err;stdout_bytes=$outRaw.Length;stderr_bytes=$errRaw.Length
  stdout_limit_bytes=$StdoutLimitBytes;stderr_limit_bytes=$StderrLimitBytes
  stdout_overflow=$stdoutOverflow;stderr_overflow=$stderrOverflow
  stdout_fault=$stdoutState.fault;stderr_fault=$stderrState.fault;capture_fault=$captureFault
  capture_accepted=$captureAccepted;capture_failure_reason=$captureFailureReason
  owned_tree_termination_requested=$terminationRequested;foreign_processes_changed=$false
 }
 if($StreamOutputFiles -or -not $captureAccepted){$record.stdout_path=$outPath;$record.stderr_path=$errPath}
 $json=$record|ConvertTo-Json -Depth 6
 [IO.File]::WriteAllText((Join-Path $OutputDirectory ($safeLabel+'.json')),$json,[Text.UTF8Encoding]::new($false))
 $json
 if(-not $captureAccepted){
  if($timedOut){throw 'PROCESS_TIMEOUT: no PASS or cleanup claim'}
  if($stdoutOverflow -or $stderrOverflow){throw 'PROCESS_OUTPUT_OVERFLOW: bounded partial capture saved; no PASS or cleanup claim'}
  throw 'PROCESS_PIPE_CAPTURE_FAILURE: no PASS or cleanup claim'
 }
}finally{
 if($process.StartInfo -and $ownedPid -and -not $process.HasExited){$process.Kill($true);[void]$process.WaitForExit(3000)}
 $cancel.Cancel();$process.Dispose();$cancel.Dispose();$stdout.Dispose();$stderr.Dispose()
}
