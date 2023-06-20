$clientId = ''
$clientSecret = ''
$tenantId = ''

$token = Get-GraphToken -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId -Scope 'https://graph.microsoft.com/.default'

$token

$token | Set-Clipboard

Start-Process 'https://jwt.ms'