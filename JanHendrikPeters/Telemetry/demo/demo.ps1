#region One-time setup
$subscription = 'compuglobalhypermeganet-webshop'
$rg = 'psconf23withJHP'
$location = 'westeurope'
$name = 'JHPai'

Set-AzContext -SubscriptionName $subscription -Scope Process
New-AzResourceGroup -Name $rg -Location $location
$ai = New-AzApplicationInsights -ResourceGroupName $rg -Name $name -location $location
$ai.ConnectionString # This is what we need to configure later
#endregion

#region Additional configuration - optional

# Need longer retention? Default is a rolling window of 90 days
$aiResource = Get-AzResource -ResourceId $ai.Id # Yup, there is no other way to write back RetentionDays
$aiResource.Properties.RetentionInDays = 365
$aiResource | Set-AzResource -Force

#region Continuous Export
<#
    Need even longer retention:
    - Continuous Export to Storage Account
    - Azure Automation Workbook and dbatools to SQL
    - ingest in PowerBI (or other BI tool)

    Possible alternatives: Stream Analytics (but where's the fun in that? ;) )
#>
#RemoveBeforeDistribution JHP --> Show Sample in Portal here...
$rndName = -join [char[]]((48..57) + (97..122) | Get-Random -Count 20)
$storage = New-AzStorageAccount -ResourceGroupName $rg -Name $rndName -Location $location -SkuName Standard_LRS
$null = New-AzStorageContainer -Name moduletelemetry -Context $storage.Context -Permission Off
$sassySplat = @{
    Context      = $storage.Context
    ExpiryTime   = (Get-Date).AddYears(50)
    Permission   = 'w'
    FullUri      = $true
    Name         = 'moduletelemetry'
    ResourceName = $rndName
    ResourceGroup= $rg
}
$sastoken = New-AzStorageContainerSASToken @sassySplat

$parma = @{
    ResourceGroupName = $rg
    Name              = 'export'
    DocumentType      = 'Request', 'Trace', 'Custom Event', 'Metric'
    StorageAccountId  = $storage.Id
    StorageLocation   = $location
    StorageSASUri     = $sastoken
    DestinationType   = 'Blob'
}
New-AzApplicationInsightsContinuousExport @parma
#endregion
#endregion

#region Usage
# Initialize Telemetry - Module initialization
$connectionSTring = 'InstrumentationKey=2970f310-272e-4eb7-a243-a6514236701d;IngestionEndpoint=https://westeurope-3.in.applicationinsights.azure.com/;LiveEndpoint=https://westeurope.livediagnostics.monitor.azure.com/'

# PsModuleDevelopment + PSFramework (ideal module for all kinds of automation needs)
Invoke-PSMDTemplate -TemplateName PSFModule -OutPath C:\tmp -Name ModuleWithTelemetry
Get-COmmand -Module TelemetryHelper

# For ease of use, TelemetryHelper uses PSFramework
code .\Telemetry\demo\ModuleWithTelemetry\internal\configurations\configuration.ps1
Set-PSFConfig -Module TelemetryHelper -Name TelemetryHelper.ModuleWithTelemetry.ConnectionString -Value $connectionString -Initialize

# Send Telemetry - Functions
code .\Telemetry\demo\ModuleWithTelemetry\functions\Remove-ContosoUser.ps1

# Metrics, Events, Exceptions and Traces
# Metrics - measurements that are aggregated and flushed automatically
Send-THMetric -MetricName UsersRemoved -Value 10 -ModuleName ModuleWithTelemetry

# Use dimensions to further partition metrics, for example
# Metric: FunctionExecution.Remove-ContosoUser.UsersRemoved
$metricParam = @{
    MetricName = 'FunctionExecution'
    Value      = 3800 #ms, ns
    ModuleName = 'ModuleWithTelemetry'
    Dimension1 = 'Remove-ContosoUser'
}
Send-THMetric @metricParam

# Events - custom data including metrics
Send-THEvent -EventName UsersRemoved -PropertiesHash @{
    UserName           = 'john', 'sally'
    SourceUserName     = $env:USERNAME
    SourceComputerName = $env:COMPUTERNAME
} -MetricsHash @{
    UsersRemoved = 10
} -ModuleName ModuleWithTelemetry

# Exceptions - errors during execution
trap # Nobody likes those ;)
{
    Send-THException -Exception $_.Exception -ModuleName ModuleWithTelemetry
}

try
{
    'john', 'sally' | Remove-ContosoUser -ErrorAction Stop
}
catch
{
    Send-THException -Exception $_.Exception -ModuleName ModuleWithTelemetry
}

# Send Telemetry - DSC Resources
code .\Telemetry\demo\ModuleWithTelemetry\internal\dscresources\JHP_EventLog.ps1

# Traces - Detailed Debug/Developer info
$traceParam = @{
    Message       = 'DSC Resource being executed'
    SeverityLevel = 'Information'
    ModuleName    = 'ModuleWithTelemetry'
}
Send-THTrace @traceParam
#endregion

#region Cleanup
Remove-AzResourceGroup -Name $rg -Force
#endregion