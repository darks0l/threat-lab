@echo off
setlocal
set "FOUNDRY_DIR=%USERPROFILE%\.foundry"
set "BIN_DIR=%FOUNDRY_DIR%\bin"
set "PATH=%BIN_DIR%;%PATH%"
mkdir "%BIN_DIR%" 2>nul
curl -sSf -L "https://raw.githubusercontent.com/foundry-rs/foundry/HEAD/foundryup/foundryup" -o "%BIN_DIR%\foundryup"
if errorlevel 1 (
    echo foundryup download failed
    exit /b 1
)
"%BIN_DIR%\foundryup"
