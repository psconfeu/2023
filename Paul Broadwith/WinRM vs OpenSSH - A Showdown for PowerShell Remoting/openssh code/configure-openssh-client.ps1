$serverIP = '192.168.88.142'

# Connect to Server with WinRM and show failure
Invoke-Command -ComputerName $serverIP -ScriptBlock { ssh -V }

# Go to the destination VM and run
# Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Set TrustedHosts to allow all connections
winrm set winrm/config/client '@{TrustedHosts="*"}'

# This fails!
winrm quickconfig

# Set TrustedHosts to allow all connections
winrm set winrm/config/client '@{TrustedHosts="*"}'

# Connect to Server with WinRM and show failure
Invoke-Command -ComputerName $serverIP -ScriptBlock { ssh -V }

# Go to the destination VM and run
# Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Get the shell on the remote host
Invoke-Command -ComputerName $serverIP -ScriptBlock { $PSVersionTable }

# Connect to Server with WinRM and show list of packages
Invoke-Command -ComputerName $serverIP -ScriptBlock { where.exe ssh }

# Get OpenSSH details
Invoke-Command -ComputerName $serverIP `
    -ScriptBlock { Get-WindowsCapability -Online | where name -like 'openssh*' `
    | select -Property pscomputername,name, state  }

# Remove OpenSSH Client and Server if installed
Invoke-Command -ComputerName $serverIP `
    -ScriptBlock { 'OpenSSH.Client~~~~0.0.1.0', 'OpenSSH.Server~~~~0.0.1.0' | `
    ForEach-Object { Remove-WindowsCapability -Name $_ -Online } }

# Check SSH is no longer installed
Invoke-Command -ComputerName $serverIP -ScriptBlock { ssh -V }

# Check SSH is no longer installed
Invoke-Command -ComputerName $serverIP -ScriptBlock { choco list }

# Install the Chocolatey package
Invoke-Command -ComputerName $serverIP -ScriptBlock { `
    choco install openssh --pre `
        --package-parameters="'/SSHAgentFeature /SSHServerFeature /KeyBasedAuthenticationFeature'" }

# Check SSH is now installed
Invoke-Command -ComputerName $serverIP -ScriptBlock { `
    Set-ExecutionPolicy Unrestricted -Force;
    Import-Module C:\ProgramData\chocolatey\helpers\chocolateyProfile.psm1; 
    refreshenv;
    ssh -V;
    where.exe ssh }

# Set PowerShell Profile to load the Chocolatey profile on startup
Invoke-Command -ComputerName $serverIP -ScriptBlock { `
    Set-Content -Value `
    'Import-Module C:\ProgramData\chocolatey\helpers\chocolateyProfile.psm1
    Write-Host "Profile loaded"' `
    -Path C:\Users\Paul\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
    }

# Check the services are running
Invoke-Command -ComputerName $serverIP -ScriptBlock { Get-Service SSH* }

ssh $serverIP

# Reset back to cmd.exe with 
# Remove-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell

# Set Windows PowerShell as default shell for SSH
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" `
  -Name DefaultShell `
  -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

# Set PowerShell as the default shell for SSH
& 'C:\Program Files\OpenSSH-Win64\Set-SSHDefaultShell.ps1' -PathSpecsToProbeForShellEXEString 'C:\Program Files\PowerShell\7\pwsh.exe'

# Show the shell winrm is using
Invoke-Command -ComputerName $serverIP -ScriptBlock { $PSVersionTable }

# To enable winrm for both Windows PowerShell and PowerShell,
# run Enable-PSRemoting -Force -SkipNetworkProfileCheck 
# from the shell you want to use
#! This doesn't work
Invoke-Command -ComputerName $serverIP -ScriptBlock { `
    & pwsh.exe -C { Enable-PSRemoting -Force -SkipNetworkProfileCheck }
    }

# Run this on the destination virtual machine from PowerShell
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Now run this to connect to PowerShell
Invoke-Command -ComputerName $serverIP -ScriptBlock { $PSVersionTable } `
    -ConfigurationName PowerShell.7
    
# Lets connect with SSH and PowerShell
# Note using the -Hostname parameter rather than -ComputerName
#! Note this fails
pwsh
New-PSSession -Hostname $serverIP

# Add the PowerShell subsystem and restart the sshd service
# Subsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo
# And run Restart-Service sshd
Invoke-Command -HostName $serverIp -ScriptBlock { $PSVersionTable }