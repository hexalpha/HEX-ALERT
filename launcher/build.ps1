param([switch]$DebugBuild)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root 'dist'
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
$RuntimeDir = Join-Path $Dist '_internal'
if (Test-Path -LiteralPath $RuntimeDir) {
    $Archive = Join-Path $PSScriptRoot 'archive'
    New-Item -ItemType Directory -Force -Path $Archive | Out-Null
    $Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    try { Move-Item -LiteralPath $RuntimeDir -Destination (Join-Path $Archive "pyside-runtime-$Stamp") -ErrorAction Stop }
    catch { Write-Warning 'An obsolete PySide runtime is locked and will be left in dist. The native launcher does not depend on it.' }
}
$Compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $Compiler)) { throw 'The Windows .NET Framework C# compiler is unavailable. Enable the Windows .NET Framework 4.x feature, then retry.' }
$ExeName = if($DebugBuild){'HEX-ALERT-DEBUG.exe'}else{'HEX-ALERT.exe'}
$ExeFile = Join-Path $Dist $ExeName
$Source = Join-Path $PSScriptRoot 'HexAlertControlCenter.cs'
$Target = if($DebugBuild){'/target:exe'}else{'/target:winexe'}
$CompilerArgs = @('/nologo',$Target,'/platform:x64','/optimize+',('/out:' + $ExeFile),'/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll',$Source)
& $Compiler @CompilerArgs
if ($LASTEXITCODE -ne 0) { throw 'C# compilation failed. The existing launcher sources and Docker data have not been changed.' }
$File = Get-Item -LiteralPath $ExeFile
$Hash = (Get-FileHash -LiteralPath $ExeFile -Algorithm SHA256).Hash
Write-Host "Built: $ExeFile"
Write-Host "Size: $($File.Length) bytes"
Write-Host "SHA-256: $Hash"
Write-Host "Build time: $($File.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
Write-Host 'Technology: native Windows Forms (.NET Framework)'
