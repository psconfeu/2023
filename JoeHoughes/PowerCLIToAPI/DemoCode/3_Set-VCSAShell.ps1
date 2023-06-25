function Set-VCSAShell {
  [CmdletBinding()]
  param (
    [Parameter( Mandatory = $true,
      Position = 0)]
    [string]$VCSAName,


    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [parameter(parametersetname = "Bash")]
    [switch]$SetBash,

    [parameter(parametersetname = "Appliance")]
    [switch]$SetApplianceShell

  )
  begin {

    if ($SetBash) {
      $command = @"
      shell
      chsh -s /bin/bash/root
      logout
"@
    }

    if ($SetApplianceShell) {
      $command = @"
      chsh -s /bin/appliancesh root
      logout
"@
    }
  }

  process {

    $SSHSession = New-SSHSession -ComputerName $VCSAName -Credential $Credential -AcceptKey
    $SSHShellStream = New-SSHShellStream -Index $SSHSession.SessionID

    foreach ($line in $command) {
      $SSHShellStream.WriteLine($line)
    }

  }

  end {

    $Result = $SSHShellStream.Read()
    $Result
    Remove-SSHSession -SSHSession $SSHSession | Out-Null

  }

}
