@echo off
rem ============================================================
rem  ipq.cmd  --  query one IP with the compat engine
rem  usage:  ipq.cmd 1.2.3.4
rem          ipq.cmd 1.2.3.4 --no-dnsbl
rem          ipq.cmd --test-keys
rem  Set IPQ_PYTHON to force a specific interpreter.
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
  echo [error] Python not found. Install Python 3.10+ and add it to PATH,
  echo         or set IPQ_PYTHON to the full path of python.exe
  exit /b 1
)

set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

"%PY%" "%~dp0compat\ip_lookup" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
