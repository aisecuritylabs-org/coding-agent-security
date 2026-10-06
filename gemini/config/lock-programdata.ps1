# Run in PowerShell opened with "Run as administrator".
$p = 'C:\ProgramData\gemini-cli'
New-Item -ItemType Directory -Force -Path $p | Out-Null

# A fresh ACL: owned by Administrators, no inherited or extra entries.
$admins = [Security.Principal.SecurityIdentifier]'S-1-5-32-544'
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)
$grants = @(
    @('S-1-5-32-544', 'FullControl'),      # Administrators
    @('S-1-5-18',     'FullControl'),      # SYSTEM
    @('S-1-5-32-545', 'ReadAndExecute')    # Users: read only
)
foreach ($g in $grants) {
    $sid = [Security.Principal.SecurityIdentifier]$g[0]
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, $g[1], 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $p -AclObject $acl

# Anything already inside takes the same owner and permissions.
Get-ChildItem -LiteralPath $p -Recurse -Force | ForEach-Object {
    icacls $_.FullName /setowner '*S-1-5-32-544' /c /q | Out-Null
    icacls $_.FullName /reset /c /q | Out-Null
}
icacls $p
