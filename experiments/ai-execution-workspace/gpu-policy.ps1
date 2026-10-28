# Fixed host-side policy bridge, not an alternative launch system.
$WorkspaceGpuPython=Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
function Invoke-WorkspaceGpuPolicy([string]$Operation,[string]$Profile,[string]$RuntimeLog=''){
 if(-not (Test-Path -LiteralPath $WorkspaceGpuPython)){throw 'GPU_POLICY_RUNTIME_UNAVAILABLE'}
 $policyArgs=@('-B',(Join-Path $PSScriptRoot 'gpu_policy.py'),$Operation,'--profile',$Profile)
 if($RuntimeLog){$policyArgs+=@('--runtime-log',$RuntimeLog)}
 $raw=& $WorkspaceGpuPython @policyArgs
 $code=$LASTEXITCODE
 try{$value=($raw -join "`n")|ConvertFrom-Json}catch{throw 'GPU_POLICY_PROTOCOL_FAILURE'}
 if($code -ne 0 -or $value.failure_code){
  if($RuntimeLog){[IO.File]::WriteAllText((Join-Path ([IO.Path]::GetDirectoryName($RuntimeLog)) 'gpu-policy-failure.json'),($value|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}
  throw ($value.failure_code+': '+$value.message)
 }
 return $value
}
function Get-WorkspaceGpuProfile($Context){
 if(-not $Context.gpu_profile -or -not $Context.gpu_config_sha256){throw 'GPU_POLICY_INVALID: trusted context has no GPU profile'}
 $profile=Invoke-WorkspaceGpuPolicy 'resolve' $Context.gpu_profile
 if($profile.config_sha256 -ne $Context.gpu_config_sha256){throw 'GPU_POLICY_CHANGED: provision a fresh context after trusted policy changes'}
 return $profile
}
