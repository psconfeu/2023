########################
## Get the YT ViewCount
########################

$ApiKey = 
$ChannelId = 

$UriSearch = "https://www.googleapis.com/youtube/v3/search"
$UriVideo = "https://www.googleapis.com/youtube/v3/videos"

$ParamsSearch = @{
    key = $ApiKey
    channelId = $ChannelId
    part = "snippet"
    order = "date"
    maxResults = "50"  # modify as needed
}

$responseSearch = Invoke-RestMethod -Uri $UriSearch -Method Get -Body $ParamsSearch

$videoList = @() 

foreach ($item in $responseSearch.items) {
    $ParamsVideo = @{
        key = $ApiKey
        id = $item.id.videoId
        part = "statistics"
    }

    $responseVideo = Invoke-RestMethod -Uri $UriVideo -Method Get -Body $ParamsVideo
    $videoList += New-Object PSObject -Property @{
        VideoId = $item.id.videoId
        VideoTitle = $item.snippet.title
        ViewCount = [int] $responseVideo.items.statistics.viewCount ## Mind the gap: [int]
    }
}

$videoList | Sort-Object -Property ViewCount -Descending

