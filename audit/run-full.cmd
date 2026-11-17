@echo off
rem ============================================================
rem  run-full.cmd  --  purity + reachability from this machine
rem  Unlike run-purity.cmd, reach.py opens a TCP connection to every
rem  node, so results depend on where you run it.
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

echo === 1/8 fetch subscription ===
if not defined SUB_URL (
  if exist v2.txt (
    echo [skip] v2.txt already present
    goto :parsed
  )
  echo [error] SUB_URL not set and no v2.txt found.
  pause
  exit /b 1
)
curl.exe -sSL -o v2.txt "%SUB_URL%"
if errorlevel 1 echo [warn] download failed, using existing v2.txt

:parsed
echo === 2/8 parse nodes ===
"%PY%" parse_sub.py v2.txt || goto :fail

echo === 3/8 resolve + geo ===
"%PY%" stage1.py || goto :fail

echo === 4/8 score every IP ===
"%PY%" batch.py || goto :fail

echo === 5/8 local TCP reachability ===
"%PY%" reach.py || goto :fail

echo === 6/8 aggregate ===
"%PY%" collect.py || goto :fail

echo === 7/8 reports ===
"%PY%" build_report.py || goto :fail
"%PY%" purity_report.py || goto :fail

echo === 8/8 clash config + excel ===
"%PY%" build_yaml.py || goto :fail
"%PY%" export_xlsx.py
if errorlevel 1 echo [hint] excel export needs openpyxl: "%PY%" -m pip install openpyxl

echo.
echo done: see out\
pause
exit /b 0

:fail
echo.
echo [failed] step above returned an error.
pause
exit /b 1

