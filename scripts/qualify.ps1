[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $Program $($Arguments -join ' ')"
    }
}

$PythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCommand) {
    $PythonCommand = Get-Command py -ErrorAction Stop
    $Python = $PythonCommand.Source
    $PythonArgs = @("-3")
} else {
    $Python = $PythonCommand.Source
    $PythonArgs = @()
}

$VersionText = & $Python @PythonArgs --version 2>&1
if ($LASTEXITCODE -ne 0) { throw "Unable to run Python: $VersionText" }
$VersionMatch = [regex]::Match([string]$VersionText, "Python (\d+)\.(\d+)")
if (-not $VersionMatch.Success) { throw "Could not parse Python version: $VersionText" }
$Major = [int]$VersionMatch.Groups[1].Value
$Minor = [int]$VersionMatch.Groups[2].Value
if (($Major -lt 3) -or (($Major -eq 3) -and ($Minor -lt 11))) {
    throw "Python 3.11 or newer is required. Found: $VersionText"
}

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Invoke-Checked $Python ($PythonArgs + @("-m", "venv", ".venv"))
}
if (-not (Test-Path $VenvPython)) { throw "Virtual environment Python was not created." }

Invoke-Checked $VenvPython @("-m", "pip", "install", "--upgrade", "pip")
Invoke-Checked $VenvPython @("-m", "pip", "install", "-e", ".[dev]", "build")
Invoke-Checked $VenvPython @("-m", "pip", "check")
Invoke-Checked $VenvPython @("-m", "ruff", "check", "src", "tests")
Invoke-Checked $VenvPython @("-m", "pytest")
Invoke-Checked $VenvPython @("-m", "compileall", "-q", "src")
if (-not $SkipBuild) {
    Invoke-Checked $VenvPython @("-m", "build", "--wheel")
}
$Nexora = Join-Path $RepoRoot ".venv\Scripts\nexora.exe"
Invoke-Checked $Nexora @("--help")
Invoke-Checked $Nexora @("settings", "diff", "--help")
Write-Host "NEXORA Sentinel qualification checks passed on this Windows host." -ForegroundColor Green
