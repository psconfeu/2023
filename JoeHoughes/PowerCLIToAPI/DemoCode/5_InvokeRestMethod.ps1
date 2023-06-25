#vCenter server
$vcenter = 'flashstack-vcenter.puretec.purestorage.com'

#BaseUri & session
$BaseUri = "https://$vcenter/rest/"
$SessionUri = $BaseUri + "com/vmware/cis/session"

#region Credential & Login
$vcCred = Get-Credential -UserName 'administrator@vsphere.local'
$authentication = [System.Convert]::ToBase64String(`
[System.Text.Encoding]::UTF8.GetBytes(`
$vcCred.UserName + ':' + $vcCred.GetNetworkCredential().Password))

$header = @{
    'Authorization' = "Basic $authentication"
}

$authResponse = (Invoke-RestMethod -Method Post -Headers $header `
-Uri $SessionUri -SkipCertificateCheck).Value
$sessionheader = @{ 'vmware-api-session-id' = $authResponse }
#endregion Credential & Login


#API Endpoints
$verUri = $BaseUri + "appliance/system/version"
$upUri = $BaseUri + "appliance/system/uptime"
$healthUri = $BaseUri + "appliance/health/applmgmt"

#Fetch data
$verResponse = Invoke-RestMethod -Method Get -Headers $sessionheader `
-Uri $verUri -SkipCertificateCheck

$healthResponse = Invoke-RestMethod -Method Get -Headers $sessionheader `
-Uri $healthUri -SkipCertificateCheck

$upResponse = Invoke-RestMethod -Method Get -Headers $sessionheader `
-Uri $upUri -SkipCertificateCheck

#Raw view
$verResponse
$verResponse.value

#Version Info
$version
$version = $verResponse.value.version

$build
$build = $verResponse.value.build

#Health
$health = $healthResponse.value
$health

#Uptime
$uptime = $upResponse.value
$uptime

$timespan = [timespan]::fromseconds($uptime)

$realtime = "$($timespan.days):$($timespan.hours):$($timespan.minutes):`
$($timespan.seconds),$($timespan.milliseconds)"

$realtime