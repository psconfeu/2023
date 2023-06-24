# Getting started
# Apply template for new project - scaffolding brought by PSModuleDevelopment
Install-Module -Name PSModuleDevelopment -Scope CurrentUser -Force
Get-PSMDTemplate
mkdir -Force -ErrorAction SilentlyContinue $home/source/repos/
$psmdSplat = @{
    TemplateName = 'AppLockerProject'
    OutPath      = "$home/source/repos/"
    Parameters   = @{DomainFqdn = 'contoso.com' }
    Name         = 'ContosoAppLocker'
}
Invoke-PSMDTemplate @psmdSplat

# Let's explore the project structure
code --add $home/source/repos/ContosoAppLocker

# Create a new git repository for your project
Set-Location -Path $home/source/repos/ContosoAppLocker
# git-scm.org, distributed source control system
git init

# The central folder that is important is called configurationdata
# It contains all raw data required to assemble policies

# Apps: Contains one yml file per application, application being a single unit that can be comprised different rule types
# Let's examine the sample app Git
code ./configurationdata/Apps/Git.yml

# So how can we add new app data?
# In order to do so, we need to download required modules first
./build/prerequisites.ps1

# Then we can make use of AppLockerFoundry to get started
Get-ChildItem -Path "C:\Program Files\7-Zip" -Recurse -File | 
Get-AlfYamlFileInfo -OutPath $home/source/repos/ContosoAppLocker/configurationdata/Apps/sevenzip.yml

code ./configurationdata/Apps/sevenzip.yml

# Those yml files are no use - yet. We can build them into valid AppLocker XML policies however
# First though we should validate their syntax
./build/validate.ps1 -TestType ConfigurationData

# It seems as if all files are valid. Let's build them into policies
./build/build.ps1 -IncludeRsop

# Hmm, 7zip is missing from Pol1. Let's add it
$content = Get-Content -Raw ./configurationdata/Policies/contoso.com/Pol1.yml | ConvertFrom-Yaml -Ordered
$content.Apps.Add('sevenzip')
$content | ConvertTo-Yaml -OutFile $home/source/repos/ContosoAppLocker/configurationdata/Policies/contoso.com/Pol1.yml -Force

# Build again
./build/build.ps1 -IncludeRsop

# Why did we go through all the trouble? Merging!
code ./configurationdata/Generics/Windows.yml # Default content for Windows baseline, make not of exceptions

# Lastly, we can publish the built artifacts
./build/publish.ps1
$gpo = Get-GPO -Name Pol1
Get-AppLockerPolicy -Ldap "LDAP://CN={$($gpo.Id)},CN=Policies,CN=System,DC=Contoso,DC=com" -Domain

# What better way to test this is there than using Pester?
./build/validate.ps1 -TestType Integration

# Bringing all of this together: A Pipeline!
code azurepipelines.yml
start https://PSCONFDO01:8080