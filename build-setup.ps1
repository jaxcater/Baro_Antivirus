$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$distApp = Join-Path $root "dist\app"
$distSetup = Join-Path $root "dist\setup"
$payloadZip = Join-Path $root "dist\BaroPayload.zip"
$outSetupExe = Join-Path $root "Baro_setup.exe"

if (Test-Path $distApp) { Remove-Item $distApp -Recurse -Force }
if (Test-Path $distSetup) { Remove-Item $distSetup -Recurse -Force }
if (Test-Path $payloadZip) { Remove-Item $payloadZip -Force }

Write-Host "[1/3] Publishing BaroAntivirus.App (win-x64 self-contained)..."
dotnet publish (Join-Path $root "src\BaroAntivirus.App\BaroAntivirus.App.csproj") `
    -c Release -r win-x64 --self-contained true `
    -p:DebugType=None -p:DebugSymbols=false `
    -o $distApp

Write-Host "[2/3] Compressing BaroPayload.zip..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($distApp, $payloadZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)

Write-Host "[3/3] Publishing Baro_setup.exe (Single-File Installer)..."
dotnet publish (Join-Path $root "src\BaroAntivirus.Setup\BaroAntivirus.Setup.csproj") `
    -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -p:EnableCompressionInSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None -p:DebugSymbols=false `
    -o $distSetup

Copy-Item (Join-Path $distSetup "Baro_setup.exe") $outSetupExe -Force
Get-Item $outSetupExe | Select-Object FullName, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB,2)}}
