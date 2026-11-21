# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Steven Lorenz. Part of sick-call.
<#
.SYNOPSIS
  Java4Shell (CVE-2026-114938) precondition collector for Windows. Read-only.
.DESCRIPTION
  Finds java.exe runtimes (bundled ones too), asks each JVM what it would do on this CPU,
  and checks running JVMs for workaround flags. Writes CSV with the same columns as
  collect_j4s.sh so j4s_triage.py can read both.
  Works in Windows PowerShell 5.1 (for example, an RMM script). AVX-512 VBMI detection needs
  PowerShell 7.4+ (.NET 8). Under 5.1, vbmi is reported as "unknown" unless the CPU model
  matches -NoVbmiModels.
.EXAMPLE
  .\Collect-J4S.ps1 -Roots 'C:\','D:\' | Export-Csv "$env:COMPUTERNAME-j4s.csv" -NoTypeInformation
#>
[CmdletBinding()]
param(
  [string[]]$Roots = @('C:\'),
  # Optional: path to Sysinternals coreinfo64.exe for VBMI detection under Windows PowerShell 5.1.
  [string]$CoreinfoPath = "$env:ProgramData\sysinternals\coreinfo64.exe",
  # CPU model fragments known to lack AVX-512 entirely (Intel client 12th gen+, pre-Zen 4 AMD).
  [string[]]$NoVbmiModels = @('i[3579]-1[2-4]\d{3}', 'Core\(TM\) Ultra', 'Ryzen \d [1-35]\d{3}', 'EPYC 7\d\d[123]')
)

$hostName = [System.Net.Dns]::GetHostEntry('').HostName
$arch = $env:PROCESSOR_ARCHITECTURE
$cpu  = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim() -replace ',', ' '

$vbmi = 'unknown'
if ($arch -ne 'AMD64') { $vbmi = 'no' }
else {
  try {
    $t = [Type]::GetType('System.Runtime.Intrinsics.X86.Avx512Vbmi')
    if ($t) { $vbmi = if ($t::IsSupported) { 'yes' } else { 'no' } }
  } catch { }
  # Sysinternals Coreinfo reports the instruction set as the OS sees it (inside a VM: what the
  # hypervisor exposes, which is the answer that matters). Feature label matched loosely on VBMI.
  if ($vbmi -eq 'unknown' -and $CoreinfoPath -and (Test-Path $CoreinfoPath)) {
    $ci = & $CoreinfoPath -accepteula -f -nobanner 2>$null | ForEach-Object { "$_" }
    $line = $ci | Where-Object { $_ -match 'VBMI' -and $_ -notmatch 'VBMI2' } | Select-Object -First 1
    if ($line) { $vbmi = if ($line -match '\*') { 'yes' } else { 'no' } }
  }
  if ($vbmi -eq 'unknown') { foreach ($m in $NoVbmiModels) { if ($cpu -match $m) { $vbmi = 'no'; break } } }
}

$mitRe = 'UseBASE64Intrinsics|UseAVX=[0-2](\D|$)|DisableIntrinsic=\S*_base64_decodeBlock'
$machineEnv = [Environment]::GetEnvironmentVariable('JAVA_TOOL_OPTIONS', 'Machine') + ' ' +
              [Environment]::GetEnvironmentVariable('_JAVA_OPTIONS', 'Machine')
$procs = @(Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue)

$javas = foreach ($r in $Roots) {
  Get-ChildItem -Path $r -Recurse -Filter java.exe -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
}

foreach ($j in ($javas | Sort-Object -Unique)) {
  # Probe with a clean environment so the result reflects the JVM default.
  $saved = @{}
  foreach ($v in '_JAVA_OPTIONS','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS') { $saved[$v] = [Environment]::GetEnvironmentVariable($v); [Environment]::SetEnvironmentVariable($v, $null) }
  $props = & $j -XshowSettings:properties -version 2>&1 | ForEach-Object { "$_" }
  $pff   = & $j -XX:+PrintFlagsFinal -version 2>$null | ForEach-Object { "$_" }
  foreach ($v in $saved.Keys) { [Environment]::SetEnvironmentVariable($v, $saved[$v]) }

  $prop = { param($n) ($props | Where-Object { $_ -match "^\s*$([regex]::Escape($n)) = " } | Select-Object -First 1) -replace '^.*? = ', '' }
  $ver = & $prop 'java.version'
  if (-not $ver) { continue }
  $flag = { param($n) (($pff | Where-Object { $_ -match "\s$n\s" } | Select-Object -First 1) -split '\s+' | Where-Object { $_ })[3] }

  $mine = @($procs | Where-Object { $_.ExecutablePath -eq $j -or $_.ExecutablePath -eq ($j -replace 'java\.exe$', 'javaw.exe') })
  $mit = 'n/a'
  if ($mine.Count -gt 0) {
    $mit = 'no'
    foreach ($p in $mine) { if ("$($p.CommandLine) $machineEnv" -match $mitRe) { $mit = 'yes' } }
  }

  [pscustomobject]@{
    host = $hostName; os = 'windows'; arch = $arch; cpu_model = $cpu; vbmi = $vbmi
    java_path = $j; java_version = $ver; runtime_version = (& $prop 'java.runtime.version')
    java_vendor = ((& $prop 'java.vendor') -replace ',', ' ')
    use_avx = (& $flag 'UseAVX'); base64_intrinsics = (& $flag 'UseBASE64Intrinsics')
    running_pids = (($mine | ForEach-Object { $_.ProcessId }) -join ';'); live_mitigation = $mit
    collected_utc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
  }
}
