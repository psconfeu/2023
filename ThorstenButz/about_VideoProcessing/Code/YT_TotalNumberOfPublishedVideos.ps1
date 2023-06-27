################################
## Total NO of videos published
################################

$ApiKey = 
$ChannelId =

$UriSearch = "https://www.googleapis.com/youtube/v3/search"
$UriChannel = "https://www.googleapis.com/youtube/v3/channels"

$ParamsChannel = @{
    key = $ApiKey
    id = $ChannelId
    part = "statistics"
}

$responseChannel = Invoke-RestMethod -Uri $UriChannel -Method Get -Body $ParamsChannel
$videoCount = $responseChannel.items.statistics.videoCount

Write-Output "Total number of published videos: $videoCount"
