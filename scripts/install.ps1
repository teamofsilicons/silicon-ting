#requires -Version 5.1
#requires -RunAsAdministrator
param([string]$Version = 'v0.1.1')
$ErrorActionPreference = 'Stop'
$repository = 'https://github.com/teamofsilicons/silicon-ting'
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($arch -eq 'Arm64') { $target = 'aarch64-pc-windows-msvc' }
elseif ($arch -eq 'X64') { $target = 'x86_64-pc-windows-msvc' }
else { throw 'Ting requires Windows x64 or ARM64.' }
$archive = "ting-$Version-$target.zip"
$temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $base = "$repository/releases/download/$Version"
    Invoke-WebRequest -UseBasicParsing "$base/$archive" -OutFile (Join-Path $temp $archive)
    Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile (Join-Path $temp 'SHA256SUMS')
    $expected = (Get-Content (Join-Path $temp 'SHA256SUMS') | Where-Object { ($_ -split '\s+')[-1] -eq $archive } | Select-Object -First 1) -split '\s+' | Select-Object -First 1
    if (!$expected -or (Get-FileHash (Join-Path $temp $archive) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.ToLowerInvariant()) { throw 'Release checksum verification failed.' }
    Expand-Archive -Path (Join-Path $temp $archive) -DestinationPath (Join-Path $temp 'release')
    $destination = Join-Path $env:ProgramFiles 'SiliconTing'
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    $existing = Get-ScheduledTask -TaskName 'SiliconTingDaemon' -ErrorAction SilentlyContinue
    if ($existing) { Stop-ScheduledTask -TaskName 'SiliconTingDaemon'; Start-Sleep -Seconds 1 }
    Copy-Item (Join-Path $temp 'release\ting.exe') $destination -Force
    Copy-Item (Join-Path $temp 'release\ting-daemon.exe') $destination -Force
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $action = New-ScheduledTaskAction -Execute (Join-Path $destination 'ting-daemon.exe')
    $triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $identity.Name), (New-ScheduledTaskTrigger -AtStartup))
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'SiliconTingDaemon' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description 'One shared Ting notification receiver for this system.' -Force | Out-Null
    Start-ScheduledTask -TaskName 'SiliconTingDaemon'
    $machinePath = [Environment]::GetEnvironmentVariable('Path','Machine')
    if (($machinePath -split ';') -notcontains $destination) { [Environment]::SetEnvironmentVariable('Path', "$machinePath;$destination", 'Machine') }
    Write-Host "Installed Ting $Version and its shared system task. Open a new terminal and run ting --help. No IAM login was performed."
} finally { Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue }
