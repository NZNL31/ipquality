@echo off
rem ============================================================
rem  install.cmd  --  add this folder to the *user* PATH
rem  usage:  install.cmd          add (then use "ipq" anywhere)
rem          install.cmd --status show current state
rem          install.cmd --remove undo
rem  Only touches HKCU\Environment\Path, no admin rights needed.
rem ============================================================
chcp 65001 >nul 2>&1
setlocal

set "PY=%IPQ_PYTHON%"
if not defined PY (
  for /f "delims=" %%P in ('where python 2^>nul') do if not defined PY set "PY=%%P"
)
if not defined PY (
  for /f "delims=" %%P in ('where py 2^>nul') do if not defined PY set "PY=%%P"
)
if not defined PY (
  echo [error] Python not found. Install Python 3.10+ or set IPQ_PYTHON.
  pause
  exit /b 1
)

set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

"%PY%" "%~dp0compat\install_path.py" %*
set "RC=%ERRORLEVEL%"

if "%~1"=="" pause
endlocal & exit /b %RC%
