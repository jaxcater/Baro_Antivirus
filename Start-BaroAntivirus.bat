@echo off
cd /d "%~dp0"
if exist "src\BaroAntivirus.App\bin\Release\net9.0-windows\BaroAntivirus.exe" (
    start "" "src\BaroAntivirus.App\bin\Release\net9.0-windows\BaroAntivirus.exe" %*
) else (
    dotnet run --project "src\BaroAntivirus.App\BaroAntivirus.App.csproj" -c Release -- %*
)
