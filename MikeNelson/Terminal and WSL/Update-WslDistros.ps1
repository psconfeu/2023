[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $DistroName
)
$a = Get-WslDistribution -Name $DistroName
$distros = $a.Name
foreach ($distro in $distros) {
    Write-Host ""
    Write-Host "Updating $distro..." -ForegroundColor Green
    wsl -d "$distro" -u root -e apt update
}
Write-Host ""
Write-Host "End script" -ForegroundColor Yellow
