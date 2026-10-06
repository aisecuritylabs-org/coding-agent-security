# Run the GitHub Copilot security audit in a throwaway, offline container (Windows).
#
# Usage (from the project you want to audit; works from CMD or PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File <repo>\copilot\audit\run.ps1 [options]
#
# Options:
#   -Report html|txt|csv|json   also save a report with how-to-fix steps
#   -ReportDir <folder>         where to save it (default %USERPROFILE%\copilot-audit-reports)
#   -NoReport                   don't ask about saving a report
#   -Json                       print JSON on screen instead of the summary
#
# Without -Report or -NoReport, you are asked at the end whether to save one.
#
# Requires Docker Desktop. The container has no network access, sees only
# the files listed below (read-only), runs unprivileged with every Linux
# capability dropped, and is deleted when it exits.

param(
    [switch]$Json,
    [ValidateSet('', 'html', 'txt', 'csv', 'json')][string]$Report = '',
    [string]$ReportDir = (Join-Path $HOME 'copilot-audit-reports'),
    [switch]$NoReport
)

# Native commands (docker) report errors through exit codes, checked below.
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$Image = if ($env:AUDIT_IMAGE) { $env:AUDIT_IMAGE } else { 'copilot-audit' }
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:DOCKER_CLI_HINTS = 'false'

# Build the image locally from the open Dockerfile, rebuilding when its sources change.
if (-not $env:AUDIT_IMAGE) {
    $src = (@("$Here\Dockerfile", "$Here\audit.sh", "$Here\mappings.json", "$Here\..\..\common\audit-lib.sh", "$Here\..\..\common\jsonc.awk", "$Here\..\..\common\gitignore.sh") |
        ForEach-Object { [IO.File]::ReadAllText($_) -replace "`r", '' }) -join ''
    $sha = [Security.Cryptography.SHA256]::Create()
    $srcHash = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($src)) | ForEach-Object { $_.ToString('x2') })).Substring(0, 16)

    $haveHash = $null; $oldId = $null
    $inspect = docker image inspect $Image 2>$null
    if ($LASTEXITCODE -eq 0) {
        $info = ($inspect | Out-String | ConvertFrom-Json)[0]
        $oldId = $info.Id
        if ($info.Config.Labels) { $haveHash = $info.Config.Labels.'org.aisecuritylabs.src-hash' }
    }
    if ($haveHash -ne $srcHash) {
        Write-Host "Building $Image from $Here\Dockerfile ..."
        docker build -q --label "org.aisecuritylabs.src-hash=$srcHash" -f "$Here\Dockerfile" -t $Image (Join-Path $Here '..\..') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Image build failed.' }
        if ($oldId) { docker image rm $oldId *> $null }
    }
}

$mounts = @()
function Add-Mount([string]$Source, [string]$Target) {
    if (Test-Path -LiteralPath $Source) { $script:mounts += @('-v', "${Source}:${Target}:ro") }
}

# Only these files, plus the project folder below, are shared with the container:
# never the Copilot CLI's config.json (authentication state), session history or logs.
$vscodeUser = Join-Path $env:APPDATA 'Code\User'
Add-Mount "$vscodeUser\settings.json" '/audit/vscode-user/settings.json'
Add-Mount "$vscodeUser\mcp.json"      '/audit/vscode-user/mcp.json'
if ((Test-Path -LiteralPath $vscodeUser) -and -not (Test-Path -LiteralPath "$vscodeUser\settings.json") -and -not (Test-Path -LiteralPath "$vscodeUser\mcp.json")) {
    $mounts += @('--tmpfs', '/audit/vscode-user:ro,size=1k')
}
$copilotHome = if ($env:COPILOT_HOME) { $env:COPILOT_HOME } else { Join-Path $HOME '.copilot' }
Add-Mount "$copilotHome\settings.json"           '/audit/copilot-home/settings.json'
Add-Mount "$copilotHome\permissions-config.json" '/audit/copilot-home/permissions-config.json'
Add-Mount "$copilotHome\mcp-config.json"         '/audit/copilot-home/mcp-config.json'

# PowerShell profiles can hold aliases that turn off the sandbox.
foreach ($p in @($PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)) {
    if ($p) { Add-Mount $p ("/audit/rc/" + (Split-Path -Leaf $p)) }
}

$cwd = (Get-Location).Path
$projectName = ''
if ($cwd -eq $HOME -or $cwd -match '^[A-Za-z]:\\$') {
    Write-Warning "Not mounting $cwd as the project. Run this from a project directory."
} else {
    Add-Mount $cwd '/audit/project'
    $projectName = Split-Path -Leaf $cwd
}

$vscodeVersion = ''; $chatVersion = ''
if (Get-Command code -ErrorAction SilentlyContinue) {
    $vscodeVersion = (code --version 2>$null | Select-Object -First 1 | Out-String).Trim()
    $chatVersion = ((code --list-extensions --show-versions 2>$null) -match '^github\.copilot-chat@' | ForEach-Object { ($_ -split '@')[1] } | Select-Object -First 1)
}

function Invoke-Audit([string]$Format) {
    docker run --rm `
        --network none `
        --read-only `
        --tmpfs /tmp:rw,noexec,nosuid,size=16m `
        --cap-drop ALL `
        --security-opt no-new-privileges `
        --pids-limit 256 `
        --memory 256m `
        -e "VSCODE_VERSION=$vscodeVersion" `
        -e "COPILOT_CHAT_VERSION=$chatVersion" `
        -e "HOST_OS=windows" `
        -e "PROJECT_NAME=$projectName" `
        @mounts `
        $Image --format $Format
}

$screenFormat = if ($Json) { 'json' } else { 'text' }
Invoke-Audit $screenFormat
$status = $LASTEXITCODE

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
    $file = Join-Path $ReportDir ("copilot-audit-{0}-{1}.{2}" -f $name, (Get-Date -Format 'yyyyMMdd-HHmmss'), $Report)
    $lines = Invoke-Audit $format
    [IO.File]::WriteAllLines($file, [string[]]$lines, [Text.UTF8Encoding]::new($true))
    Write-Host "Report saved: $file"
}

exit $status
