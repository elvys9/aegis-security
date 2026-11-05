#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$service = Get-Service -Name 'AegisSecurity' -ErrorAction SilentlyContinue
if ($null -eq $service) { Write-Output 'AegisSecurity is not installed.'; return }
if ($service.Status -ne 'Stopped') {
    Stop-Service -Name 'AegisSecurity'
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
}
& "$env:SystemRoot\System32\sc.exe" delete AegisSecurity
if ($LASTEXITCODE -ne 0) { throw "SCM deletion failed: $LASTEXITCODE" }
Write-Output 'Service registration removed. Executable, configuration and findings retained for manual review.'
