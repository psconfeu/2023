# You can also use common modules to obtain a token with a certificate. For example, the AzureAD module:
# # Provide the path to your .pfx certificate to use
$CertPath = ''
#
# # Provide the ClientId and TenantId of your Azure AD App Registration and the scope you want to request
$clientId = ''
$tenantId = ''
# $scope = 'https://graph.microsoft.com/.default'
#
# # Either provide the certificate as a .pfx file (in this case without a password)
$cert = Get-PfxCertificate -FilePath $CertPath -NoPromptForPassword
# # Or refer to the certificate in the local machine or currentuser store
# $cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $(Get-PfxCertificate -FilePath $CertPath -NoPromptForPassword).Thumbprint}
# $cert = Get-ChildItem -Path cert:\CurrentUser\My | Where-Object {$_.Thumbprint -eq $(Get-PfxCertificate -FilePath $CertPath -NoPromptForPassword).Thumbprint}

#

 ## Microsoft.Graph - cert needs to be installed in the current user store, not local machine
 # https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=powershell#request
# Install-Module -Name Microsoft.Graph
# Import-Module -Name Microsoft.Graph

$MSToken = Connect-MgGraph -CertificateThumbprint $cert.Thumbprint -ClientId $clientid -TenantId $tenantID
$MSToken #token not shown due to security reasons
# Get all users
Import-Module Microsoft.Graph.Users
$MgUsers = Get-MgUser
$MgUsers

## Minigraph - no need to install cert, just present certificate
# Install-Module -Name Minigraph
# DO NOTE CONFLICTING CMDLETS if you have MgGraph installed, hence using a prefix
Import-Module -Name Minigraph -prefix PF

$MiniGraphToken = Connect-PFGraphCertificate -ClientId $clientId -TenantId $tenantId -Certificate $cert
$MiniGraphToken #token not shown due to security reasons
#Get all users
Invoke-PFGraphRequest -Query 'users' 