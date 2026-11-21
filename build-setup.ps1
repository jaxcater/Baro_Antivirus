$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$distDir = Join-Path $root "dist"
$distApp = Join-Path $distDir "app"
$distSetupStage = Join-Path $distDir "setup-stage"
$distPayload = Join-Path $distDir "payload-delta"
$distSetup = Join-Path $distDir "setup"
$payloadZip = Join-Path $distDir "BaroPayload.zip"
$portableZip = Join-Path $distDir "BaroAntivirus-Portable-win-x64.zip"
$outSetupExe = Join-Path $root "Baro_setup.exe"

foreach ($p in @($distApp, $distSetupStage, $distPayload, $distSetup)) {
    if (Test-Path $p) { Remove-Item $p -Recurse -Force }
}
foreach ($f in @($payloadZip, $portableZip)) {
    if (Test-Path $f) { Remove-Item $f -Force }
}
New-Item -ItemType Directory -Path $distPayload -Force | Out-Null

Write-Host "[1/4] Publishing BaroAntivirus.App (win-x64 self-contained, en;vi)..."
dotnet publish (Join-Path $root "src\BaroAntivirus.App\BaroAntivirus.App.csproj") `
    -c Release -r win-x64 --self-contained true `
    -p:DebugType=None -p:DebugSymbols=false `
    -o $distApp
if ($LASTEXITCODE -ne 0) { throw "Publish App failed" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($distApp, $portableZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)

Write-Host "[2/4] Staging BaroAntivirus.Setup runtime baseline..."
dotnet publish (Join-Path $root "src\BaroAntivirus.Setup\BaroAntivirus.Setup.csproj") `
    -c Release -r win-x64 --self-contained true `
    -p:DebugType=None -p:DebugSymbols=false `
    -o $distSetupStage
if ($LASTEXITCODE -ne 0) { throw "Stage Setup failed" }

Write-Host "[3/4] Deduplicating shared .NET 9 / WPF managed runtime into delta BaroPayload.zip..."
# Core native host/CLR files are statically linked or hidden inside singlefilehost.exe, so always pack them in BaroPayload.zip
$alwaysIncludeNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
@(
    "hostfxr.dll", "hostpolicy.dll", "coreclr.dll", "clrjit.dll", "clrgc.dll", "clrgcexp.dll",
    "clretwrc.dll", "mscordaccore.dll", "mscordbi.dll", "mscorrc.dll",
    "Microsoft.DiaSymReader.Native.amd64.dll", "msquic.dll", "System.IO.Compression.Native.dll", "createdump.exe"
) | ForEach-Object { [void]$alwaysIncludeNames.Add($_) }

$appFiles = Get-ChildItem $distApp -Recurse -File
$deltaCount = 0
$sharedCount = 0
foreach ($f in $appFiles) {
    $rel = $f.FullName.Substring($distApp.Length).TrimStart('\', '/')
    $mustInclude = $alwaysIncludeNames.Contains($f.Name) -or ($f.Name -like "mscordaccore_*")
    $stageCounterpart = Join-Path $distSetupStage $rel
    $isIdentical = $false
    if (-not $mustInclude -and (Test-Path $stageCounterpart)) {
        $sf = Get-Item $stageCounterpart
        if ($sf.Length -eq $f.Length) {
            $h1 = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
            $h2 = (Get-FileHash $sf.FullName -Algorithm SHA256).Hash
            if ($h1 -eq $h2) { $isIdentical = $true }
        }
    }
    if ($isIdentical) {
        $sharedCount++
    } else {
        $dest = Join-Path $distPayload $rel
        $destParent = Split-Path -Parent $dest
        if (-not (Test-Path $destParent)) { New-Item -ItemType Directory -Path $destParent -Force | Out-Null }
        Copy-Item $f.FullName $dest -Force
        $deltaCount++
    }
}
Write-Host "    Shared runtime files reused: $sharedCount | Delta app+native files packed: $deltaCount"
[System.IO.Compression.ZipFile]::CreateFromDirectory($distPayload, $payloadZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)

Write-Host "[4/4] Publishing Baro_setup.exe (Compressed Single-File Installer)..."
dotnet publish (Join-Path $root "src\BaroAntivirus.Setup\BaroAntivirus.Setup.csproj") `
    -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -p:EnableCompressionInSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:IncludeAllContentForSelfExtract=true `
    -p:DebugType=None -p:DebugSymbols=false `
    -o $distSetup
if ($LASTEXITCODE -ne 0) { throw "Publish Setup failed" }

Copy-Item (Join-Path $distSetup "Baro_setup.exe") $outSetupExe -Force
Get-Item $outSetupExe, $portableZip | Select-Object Name, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB,2)}}
