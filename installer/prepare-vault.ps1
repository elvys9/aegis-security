$ErrorActionPreference = 'Stop'
# Executed only by the elevated installer. Never recursively changes user vault ACLs.
try {
    $base = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AegisSecurity'
    $users = Join-Path $base 'Users'
    $admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $builtinUsers = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $creator = [System.Security.Principal.SecurityIdentifier]::new('S-1-3-0')
    foreach ($path in @($base, $users)) {
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Unsafe vault parent: $path" }
            $owner = (Get-Acl -LiteralPath $path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($owner -notin @($admins.Value, $system.Value)) { throw "Unexpected vault parent owner: $path" }
        } else {
            New-Item -ItemType Directory -Path $path | Out-Null
        }
        $acl = [System.Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner($admins)
        foreach ($principal in @($admins, $system)) {
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        # Traversal/read only, applying to this parent, never inherited by vaults.
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($builtinUsers, 'ReadAndExecute', 'None', 'None', 'Allow'))
        if ($path -eq $users) {
            # Users may create their own SID directory; no write/delete on siblings.
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($builtinUsers, 'CreateDirectories', 'None', 'None', 'Allow'))
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($creator, 'FullControl', 'ContainerInherit,ObjectInherit', 'InheritOnly', 'Allow'))
        }
        Set-Acl -LiteralPath $path -AclObject $acl
    }
    exit 0
} catch {
    Write-Error $_
    exit 1
}
