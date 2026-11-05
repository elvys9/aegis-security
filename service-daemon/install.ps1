#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$BinaryPath)
$ErrorActionPreference = 'Stop'
$serviceName = 'AegisSecurity'
$installDir = Join-Path $env:ProgramFiles 'AegisSecurity'
$dataDir = Join-Path $env:ProgramData 'AegisSecurityService'
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Service already installed. Stop and uninstall it before updating.' }
$source = (Resolve-Path -LiteralPath $BinaryPath).Path
if ([IO.Path]::GetExtension($source) -ne '.exe') { throw 'Supply a reviewed release executable.' }
function Assert-NoReparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point refused: $($item.FullName)" }
        $item = $item.Parent
    }
}
function Protect-Directory([string]$Path) {
    # Refuse preexisting directories: their contents might have been planted by a standard user.
    if (Test-Path -LiteralPath $Path) { throw "Destination already exists; review it manually before installation: $Path" }
    Assert-NoReparse (Split-Path -Parent $Path)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl.SetOwner($admin)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($admin, $system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    # .NET Framework overload creates the directory with its protected ACL atomically.
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
    Assert-NoReparse $Path
    # CreateDirectory can return an existing directory after a creation race.
    # Verify its actual ACL before writing privileged files into it.
    $actual = Get-Acl -LiteralPath $Path
    $owner = $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-32-544', 'S-1-5-18') -or -not $actual.AreAccessRulesProtected) { throw "Untrusted destination ACL: $Path" }
    foreach ($rule in $actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544', 'S-1-5-18')) { throw "Unexpected destination access grant: $Path" }
    }
}
Protect-Directory $installDir
Protect-Directory $dataDir
$destination = Join-Path $installDir 'aegis-service.exe'
Copy-Item -LiteralPath $source -Destination $destination
# Empty roots intentionally fail closed until an administrator chooses scope.
'{"roots":[],"interval_seconds":3600,"workers":2,"watch":false}' | Set-Content -LiteralPath (Join-Path $dataDir 'service.json') -Encoding Ascii
foreach ($file in @($destination, (Join-Path $dataDir 'service.json'))) {
    $fileAcl = Get-Acl -LiteralPath $file
    $fileAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    Set-Acl -LiteralPath $file -AclObject $fileAcl
}
New-Service -Name $serviceName -DisplayName 'Aegis Security scanner (optional)' -BinaryPathName ('"' + $destination + '"') -StartupType Manual -Description 'Optional user-mode scheduled scanner. Logs findings; does not block execution or quarantine files.' | Out-Null
Write-Output "Installed as LocalSystem, stopped. Review $dataDir\service.json, choose absolute local roots, then explicitly run Start-Service AegisSecurity."
