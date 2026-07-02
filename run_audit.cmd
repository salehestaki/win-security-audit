@echo off
setlocal
cd /d "%~dp0"

set "EXE="
if exist "%CD%\SecurityAudit.exe" set "EXE=%CD%\SecurityAudit.exe"
if exist "%CD%\dist\SecurityAudit.exe" set "EXE=%CD%\dist\SecurityAudit.exe"
if exist "%CD%\dist\SecurityAudit\SecurityAudit.exe" set "EXE=%CD%\dist\SecurityAudit\SecurityAudit.exe"

if defined EXE (
  "%EXE%" %*
  set "RC=%ERRORLEVEL%"
) else (
  set "PYTHONPATH=%CD%\src;%PYTHONPATH%"
  py -3 -m win_security_audit %*
  set "RC=%ERRORLEVEL%"
  if not "%RC%"=="0" (
    python -m win_security_audit %*
    set "RC=%ERRORLEVEL%"
  )
)

echo.
if not "%RC%"=="0" (
  echo Security Audit finished with exit code %RC%.
) else (
  echo Security Audit finished successfully.
)
pause
exit /b %RC%
