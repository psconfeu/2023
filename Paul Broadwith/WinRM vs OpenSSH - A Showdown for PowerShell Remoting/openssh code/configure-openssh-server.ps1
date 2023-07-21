# Check if OpenSSH is present on the OS
Get-WindowsCapability -Online | where name -like 'openssh*'

# Check the version of OpenSSH installed
ssh -V

# Remove OpenSSH Client and Server if installed
'OpenSSH.Client~~~~0.0.1.0', 'OpenSSH.Server~~~~0.0.1.0' | `
    ForEach-Object { Remove-WindowsCapability -Name $_ -Online }

# Check if OpenSSH is still present  on the OS
Get-WindowsCapability -Online | Where-Object name -Like 'openssh*'

# Make sure ssh is not available!
ssh -V

where.exe ssh

# Install the Chocolatey package
choco install openssh --pre --package-parameters="'/SSHAgentFeature /SSHServerFeature /KeyBasedAuthenticationFeature'"

# Import the Chocolatey Helper
Import-Module C:\ProgramData\chocolatey\helpers\chocolateyProfile.psm1
refreshenv

ssh

where.exe ssh

# Check the services are running
Get-Service SSH*

# Reset back to cmd.exe with 
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

