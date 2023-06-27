######################################################################
## OpenAI ⚭ YouTube
## https://chat.openai.com/share/3b211a18-4d2a-4e1d-ba32-3173284b8bf5
######################################################################

$ApiKey = 
$ChannelId =

$UriSearch = "https://www.googleapis.com/youtube/v3/search"
$UriVideo = "https://www.googleapis.com/youtube/v3/videos"
$ParamsSearch = @{
    key = $ApiKey
    channelId = $ChannelId
    part = "snippet"
    order = "date"
    maxResults = "450"  # modify as needed
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
        ViewCount = $responseVideo.items.statistics.viewCount
    }
}

$videoList | Sort-Object -Property ViewCount -Descending
"Total number of published videos: $videoCount"
