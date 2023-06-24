#header
function Get-VM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [string[]]$VMName
    )
    $cmdParms = @{
        'ComputerName' = $ComputerName 
        'ConfigurationName' = $script:EndpointName
    }
    if ($PSBoundParameters.ContainsKey('VMName')) {
        Invoke-Command @cmdParms -ScriptBlock { Get-RBACVM -VMName $using:VMName }
    } else {
        Invoke-Command @cmdParms -ScriptBlock { Get-RBACVM }
    }
}
#region footer

#endregion
$script:EndpointName = 'MetaBPA.HyperVRBAC'
Export-ModuleMember -Function @('Get-VM')
