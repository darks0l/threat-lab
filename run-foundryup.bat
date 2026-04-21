@echo off
cd /d "%~dp0"
setlocal
set "FOUNDRY_DIR=%USERPROFILE%\.foundry"
set "BIN_DIR=%FOUNDRY_DIR%\bin"
mkdir "%BIN_DIR%" 2>nul
curl -sSf -L "https://raw.githubusercontent.com/foundry-rs/foundry/HEAD/foundryup/foundryup" -o "%BIN_DIR%\foundryup"
if errorlevel 1 (
    echo ERROR: foundryup download failed
    pause
    exit /b 1
)
echo Running foundryup...
"%BIN_DIR%\foundryup"
if errorlevel 1 (
    echo ERROR: foundryup install failed
    pause
    exit /b 1
)
echo.
echo Foundry installed. bin dir: %BIN_DIR%
dir "%BIN_DIR%"
pause
