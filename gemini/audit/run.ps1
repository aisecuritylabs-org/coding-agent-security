# Run the Gemini CLI and Code Assist security audit in a throwaway, offline container (Windows).
#
# Usage (from the project you want to audit; works from CMD or PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File <repo>\gemini\audit\run.ps1 [options]
#
# Options:
#   -Report html|txt|csv|json   also save a report with how-to-fix steps
#   -ReportDir <folder>         where to save it (default %USERPROFILE%\gemini-audit-reports)
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
    [string]$ReportDir = (Join-Path $HOME 'gemini-audit-reports'),
    [switch]$NoReport
)

# Native commands (docker) report errors through exit codes, checked below.
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$Image = if ($env:AUDIT_IMAGE) { $env:AUDIT_IMAGE } else { 'gemini-audit' }
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
# never oauth_creds.json, google_accounts.json, chat history or anything else in ~/.gemini.
$geminiHome = Join-Path $HOME '.gemini'
Add-Mount "$geminiHome\settings.json" '/audit/gemini-home/settings.json'
Get-ChildItem -LiteralPath "$geminiHome\policies" -Filter '*.toml' -File -ErrorAction SilentlyContinue | ForEach-Object {
    Add-Mount $_.FullName "/audit/gemini-home/policies/$($_.Name)"
}
# Only each extension's manifest, never its code.
Get-ChildItem -LiteralPath "$geminiHome\extensions" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '[:,]' } | ForEach-Object {
    Add-Mount (Join-Path $_.FullName 'gemini-extension.json') "/audit/gemini-home/extensions/$($_.Name)/gemini-extension.json"
}
# VS Code user settings, for the Gemini Code Assist agent setting.
Add-Mount (Join-Path $env:APPDATA 'Code\User\settings.json') '/audit/vscode-user/settings.json'

# Machine-wide files every Gemini CLI user on this computer loads.
$programData = Join-Path $env:ProgramData 'gemini-cli'
Add-Mount "$programData\settings.json" '/audit/system/settings.json'
Add-Mount "$programData\system-defaults.json" '/audit/system/system-defaults.json'

# Who can change the ProgramData folder? If anyone other than administrators can
# write it, or own it, one local user can plant settings, such as a session-start hook, that every Gemini CLI user on the machine loads
# (reported by Cymulate). The folder and everything in it must be owned by, and
# writable only by, Administrators, SYSTEM or TrustedInstaller.
# GEMINI_PROGRAMDATA_DIR overrides the path for testing.
function Get-ProgramDataState([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 'missing' }
    $trusted = @(
        'S-1-5-32-544',                                                    # Administrators
        'S-1-5-18',                                                        # SYSTEM
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',  # TrustedInstaller
        'S-1-3-0'                                                          # CREATOR OWNER: only whoever could already create
    )
    # Any right that lets someone change files or permissions, including generic rights.
    $writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000
    try {
        $items = @(Get-Item -LiteralPath $Path -Force -ErrorAction Stop)
        # Every file and folder inside is checked. A folder this config path should never hold
        # thousands of items, so past 5000 the result is unknown rather than a partial pass.
        $children = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop)
        if ($children.Count -gt 5000) { return 'unknown' }
        $items += $children
        foreach ($item in $items) {
            $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            $owner = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
            if ($trusted -notcontains $owner) { return 'user-writable' }
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -ne 'Allow') { continue }
                if (([int64]$rule.FileSystemRights -band $writeMask) -eq 0) { continue }
                if ($trusted -notcontains $rule.IdentityReference.Value) { return 'user-writable' }
            }
        }
        return 'admin-only'
    } catch {
        return 'unknown'
    }
}

$programDataDir = if ($env:GEMINI_PROGRAMDATA_DIR) { $env:GEMINI_PROGRAMDATA_DIR } else { $programData }
$programDataState = Get-ProgramDataState $programDataDir

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

$geminiVersion = ''
if (Get-Command gemini -ErrorAction SilentlyContinue) {
    $geminiVersion = (gemini --version 2>$null | Select-Object -First 1 | Out-String).Trim()
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
        -e "GEMINI_VERSION=$geminiVersion" `
        -e "HOST_OS=windows" `
        -e "PROGRAMDATA_STATE=$programDataState" `
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
    $file = Join-Path $ReportDir ("gemini-audit-{0}-{1}.{2}" -f $name, (Get-Date -Format 'yyyyMMdd-HHmmss'), $Report)
    $lines = Invoke-Audit $format
    [IO.File]::WriteAllLines($file, [string[]]$lines, [Text.UTF8Encoding]::new($true))
    Write-Host "Report saved: $file"
}

exit $status
