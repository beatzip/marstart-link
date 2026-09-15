@echo off
REM Embeds requireAdministrator manifest into the MARSTART LINK binary.
REM Run AFTER `tauri build` completes.
REM Usage: embed_manifest.bat <path_to_exe>
set "MT="
for /f "delims=" %%i in ('dir /b /s "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\mt.exe" 2^>nul') do set "MT=%%i"
if not defined MT (
echo ERROR: mt.exe not found under Windows Kits\10\bin -- install the Windows SDK (Desktop Build Tools)
exit /b 1
)
if "%~1"=="" (
echo Usage: embed_manifest.bat ^<path_to_exe^>
exit /b 1
)
%MT% -manifest "C:\Users\User\Desktop\marstart-link-main\src-tauri\src-tauri.manifest" -outputresource:"%~1;#1" -nologo
if errorlevel 1 (
echo ERROR: mt.exe failed
exit /b 1
)
echo Manifest embedded successfully: requireAdministrator
