@echo off
rem ============================================================
rem  ipq-run.cmd  --  run the upstream IPQuality shell script
rem                  (tests the *local* egress IP, needs bash+coreutils)
rem  usage:  ipq-run.cmd        dual stack
rem          ipq-run.cmd -4     IPv4 only
rem          ipq-run.cmd -6     IPv6 only
rem          ipq-run.cmd 1.2.3.4  (delegates to compat\ip_lookup)
rem  Set IPQ_BASH to force a specific bash.exe.
rem ============================================================
chcp 65001 >nul 2>&1
setlocal

set "BASH=%IPQ_BASH%"
if not defined BASH (
  for /f "delims=" %%P in ('where bash 2^>nul') do if not defined BASH set "BASH=%%P"
)
if not defined BASH (
  if exist "%ProgramFiles%\Git\bin\bash.exe" set "BASH=%ProgramFiles%\Git\bin\bash.exe"
)
if not defined BASH (
  if exist "%ProgramFiles(x86)%\Git\bin\bash.exe" set "BASH=%ProgramFiles(x86)%\Git\bin\bash.exe"
)
if not defined BASH (
  if exist "%LOCALAPPDATA%\Programs\Git\bin\bash.exe" set "BASH=%LOCALAPPDATA%\Programs\Git\bin\bash.exe"
)

if not defined BASH (
  echo [error] bash.exe not found. Install Git for Windows,
  echo         or set IPQ_BASH to ...\Git\bin\bash.exe
  exit /b 1
)

"%BASH%" --noprofile --norc "%~dp0run.sh" %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
