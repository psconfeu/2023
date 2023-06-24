$requiredModules = @(
    @{
        Name           = 'Pester'
        MinimumVersion = [System.Version]'5.2.2'
        MaximumVersion = [System.Version]'5.999999'
    },
    @{
        Name           = 'PSScriptAnalyzer'
        MinimumVersion = [System.Version]'1.18.2'
        MaximumVersion = [System.Version]'1.99.99'
    }
)

# Save any required modules that are not already present on the machine into the /modules folder
foreach ($module in $requiredModules) {
    $localModule = Get-Module -Name $module.Name -ListAvailable | Where-Object { ($_.version -ge $module.MinimumVersion) -and ($_.version -le $module.MaximumVersion) }
    if (-not $localModule) {
        Install-Module @module -Repository 'PSGallery' -ErrorAction 'Stop'
    }
}