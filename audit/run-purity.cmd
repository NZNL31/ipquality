@echo off
rem ============================================================
rem  run-purity.cmd  --  IP purity only (no probing from your side)
rem  Nothing here touches the nodes themselves: scores come from
rem  third-party databases, only the target IP is sent.
rem
rem  Set SUB_URL to your subscription file before running, e.g.
rem      set SUB_URL=https://example.com/sub.txt
rem  or drop a v2.txt next to this script and it will be reused.
rem ============================================================
chcp 65001 >nul 2>&1
setlocal
cd /d "%~dp0"

set "PY=%IPQ_PYTHON%"
if not defined PY (
  for /f "delims=" %%P in ('where python 2^>nul') do if not defined PY set "PY=%%P"
)
if not defined PY (
  echo [error] Python not found. Install Python 3.10+ or set IPQ_PYTHON.
  pause
  exit /b 1
)
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

echo === 1/5 fetch subscription ===
if not defined SUB_URL (
  if exist v2.txt (
    echo [skip] v2.txt already present
    goto :parsed
  )
  echo [error] SUB_URL not set and no v2.txt found.
  echo         set SUB_URL=https://example.com/your-sub.txt
  pause
  exit /b 1
)
curl.exe -sSL -o v2.txt "%SUB_URL%"
if errorlevel 1 (
  echo [warn] download failed, falling back to existing v2.txt
)

:parsed
echo === 2/5 parse nodes ===
"%PY%" parse_sub.py v2.txt || goto :fail

echo === 3/5 resolve + geo ===
"%PY%" stage1.py || goto :fail

echo === 4/5 score every IP (interruptible, resumes) ===
"%PY%" batch.py || goto :fail

echo === 5/5 aggregate + purity ranking ===
"%PY%" collect.py || goto :fail
"%PY%" purity_report.py || goto :fail

echo.
echo done: out\report-purity-top50.md
pause
exit /b 0

:fail
echo.
echo [failed] step above returned an error.
pause
exit /b 1

