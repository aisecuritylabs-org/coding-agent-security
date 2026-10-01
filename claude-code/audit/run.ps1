# Run the Claude Code security audit in a throwaway, offline container (Windows).
#
# Usage (from the project you want to audit; works from CMD or PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File <repo>\claude-code\audit\run.ps1 [options]
#
# Options:
#   -Report html|txt|csv|json   also save a report with how-to-fix steps
#   -ReportDir <folder>         where to save it (default %USERPROFILE%\claude-code-audit-reports)
#   -NoReport                   don't ask about saving a report
#   -Json                       print JSON on screen instead of the summary
#
# Without -Report or -NoReport, you are asked at the end whether to save one.
#
# Requires Docker Desktop. The container has no network access, sees only
# the files listed below (read-only), runs unprivileged with every Linux
# capability dropped, and is deleted when it exits. Reports are printed by
# the container and saved by this script; the container never gets write access.

param(
    [switch]$Json,
    [ValidateSet('', 'html', 'txt', 'csv', 'json')][string]$Report = '',
    [string]$ReportDir = (Join-Path $HOME 'claude-code-audit-reports'),
    [switch]$NoReport
)

# Native commands (docker) report errors through exit codes, checked below.
# 'Stop' would turn docker's normal stderr output into terminating errors.
$ErrorActionPreference = 'Continue'
# Read docker's output as UTF-8 so reports keep non-ASCII characters intact.
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$Image = if ($env:AUDIT_IMAGE) { $env:AUDIT_IMAGE } else { 'claude-code-audit' }
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:DOCKER_CLI_HINTS = 'false'   # no Docker Desktop "what's next" adverts

# Build the image locally from the open Dockerfile. The image is labelled with
# a fingerprint of its source files, so it is rebuilt whenever they change.
if (-not $env:AUDIT_IMAGE) {
    $src = (@("$Here\Dockerfile", "$Here\audit.sh", "$Here\mappings.json", "$Here\..\tests\test-hooks.sh") |
        ForEach-Object { [IO.File]::ReadAllText($_) -replace "`r", '' }) -join ''
    $sha = [Security.Cryptography.SHA256]::Create()
    $srcHash = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($src)) | ForEach-Object { $_.ToString('x2') })).Substring(0, 16)

    # Read labels as JSON: Windows PowerShell mangles quotes inside --format templates.
    $haveHash = $null; $oldId = $null
    $inspect = docker image inspect $Image 2>$null
    if ($LASTEXITCODE -eq 0) {
        $info = ($inspect | Out-String | ConvertFrom-Json)[0]
        $oldId = $info.Id
        if ($info.Config.Labels) { $haveHash = $info.Config.Labels.'org.aisecuritylabs.src-hash' }
    }
    if ($haveHash -ne $srcHash) {
        Write-Host "Building $Image from $Here\Dockerfile ..."
        docker build -q --label "org.aisecuritylabs.src-hash=$srcHash" -f "$Here\Dockerfile" -t $Image (Join-Path $Here '..') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Image build failed.' }
        if ($oldId) { docker image rm $oldId *> $null }   # drop the outdated image
    }
}

$mounts = @()
function Add-Mount([string]$Source, [string]$Target) {
    if (Test-Path -LiteralPath $Source) { $script:mounts += @('-v', "${Source}:${Target}:ro") }
}

# Only these files, plus the project folder below, are shared with the container. Never transcripts, ~/.ssh or cloud credential folders.
Add-Mount "$HOME\.claude\settings.json" '/audit/home-claude/settings.json'
Add-Mount "$HOME\.claude\hooks"         '/audit/home-claude/hooks'
Add-Mount "$HOME\.claude.json"          '/audit/claude.json'

# The current directory is audited as the project, but never your whole home.
$cwd = (Get-Location).Path
$projectName = ''
if ($cwd -eq $HOME -or $cwd -match '^[A-Za-z]:\\$') {
    Write-Warning "Not mounting $cwd as the project. Run this from a project directory."
} else {
    Add-Mount $cwd '/audit/project'
    $projectName = Split-Path -Leaf $cwd
}

$version = ''
if (Get-Command claude -ErrorAction SilentlyContinue) { $version = (claude --version 2>$null | Out-String).Trim() }

function Invoke-Audit([string]$Format) {
    docker run --rm `
        --network none `
        --read-only `
        --tmpfs /tmp:rw,noexec,nosuid,size=16m `
        --cap-drop ALL `
        --security-opt no-new-privileges `
        --pids-limit 256 `
        --memory 256m `
        -e "CLAUDE_VERSION=$version" `
        -e "HOST_OS=windows" `
        -e "PROJECT_NAME=$projectName" `
        @mounts `
        $Image --format $Format
}

$screenFormat = if ($Json) { 'json' } else { 'text' }
Invoke-Audit $screenFormat
$status = $LASTEXITCODE

# Offer a report file with how-to-fix steps.
if (-not $Report -and -not $NoReport -and -not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
    Write-Host ''
    $answer = Read-Host 'Save a report with how-to-fix steps? [h]tml, [t]ext, [c]sv, [j]son, [n]o (default n)'
    switch -Regex ($answer) {
        '^(h|html)$'       { $Report = 'html' }
        '^(t|txt|text)$'   { $Report = 'txt' }
        '^(c|csv)$'        { $Report = 'csv' }
        '^(j|json)$'       { $Report = 'json' }
    }
}

if ($Report) {
    $format = @{ html = 'html'; txt = 'report'; csv = 'csv'; json = 'json' }[$Report]
    New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
    $name = if ($projectName) { $projectName } else { 'home' }
    $file = Join-Path $ReportDir ("claude-code-audit-{0}-{1}.{2}" -f $name, (Get-Date -Format 'yyyyMMdd-HHmmss'), $Report)
    $lines = Invoke-Audit $format
    # UTF-8 with a byte-order mark so Excel and Notepad detect the encoding.
    [IO.File]::WriteAllLines($file, [string[]]$lines, [Text.UTF8Encoding]::new($true))
    Write-Host "Report saved: $file"
}

exit $status
