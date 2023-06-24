# Install-Module -Name Microsoft.PowerShell.SecretManagement -Repository PSGallery
# Install-Module SecretManagement.KeePass

Import-Module Microsoft.PowerShell.SecretManagement 
Import-Module SecretManagement.KeePass

$vaultFile = Join-Path -Path $PSScriptRoot -ChildPath 'PSCONF-Vault.kdbx'

if (test-Path $vaultFile) {
    if ($null -eq (Get-SecretVault -Name 'PSConfEU-Vault' -ErrorAction SilentlyContinue)) {
        Register-SecretVault -Name 'PSConfEU-Vault' -ModuleName 'SecretManagement.Keepass' -VaultParameters @{
            Path = $vaultFile
            UseMasterPassword = $true
        }
    }
    if (Test-SecretVault -Name 'PSConfEU-Vault') {
        $vSphereCred = Get-Secret -Name 'vSphere' -Vault 'PSConfEU-Vault'
        Write-Host "Name: $($vSphereCred.UserName)"
        Write-Host "Password: $($vSphereCred.GetNetworkCredential().Password)"
    }
} else {
    Write-Warning "Vault not found: $vaultFile"
}