# ============================================================
#  ipq.ps1  --  PowerShell launcher (UTF-8 safe)
#  usage:  .\ipq.ps1 1.2.3.4
#          .\ipq.ps1 1.2.3.4 --no-dnsbl
#          .\ipq.ps1 --test-keys
#  If script execution is blocked, use .\ipq.cmd instead, or run
#  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
# ============================================================
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUTF8 = '1'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = $env:IPQ_PYTHON
if (-not $py) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source }
}
if (-not $py) {
    $cmd = Get-Command py -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source }
}
if (-not $py) {
    Write-Error 'Python not found. Install Python 3.10+ or set IPQ_PYTHON.'
    exit 1
}

& $py (Join-Path $here 'compat\ip_lookup') @args
exit $LASTEXITCODE
