Param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('simple','advanced')]
    [string]$Type = "simple",

    [Parameter(Mandatory = $false)]
    [string]$TestLocation = ".\src\default",

    [Parameter(Mandatory = $false)]
    [switch]$OutputResults
)

# initialize
.\tests\init\init.ps1

# test
$pestercommand = Get-Command Invoke-Pester
"`n`tSTATUS: Testing with PowerShell $($PSVersionTable.PSVersion.ToString())"
"`tSTATUS: Testing with Pester $($pestercommand.version)`n"

$container = New-PesterContainer -Path (Join-Path -Path $PSScriptRoot -ChildPath "tests/$Type")
$container.Data = @{
    TestLocation = $TestLocation
}

$configuration = New-PesterConfiguration
$configuration.Run.PassThru = $true
$configuration.Run.Container = $container

if ($PSBoundParameters.OutputResults.IsPresent) {
    # Outputting to file when running in a pipeline
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputPath = "pssa.testresults.xml"
}

Invoke-Pester -Configuration $configuration