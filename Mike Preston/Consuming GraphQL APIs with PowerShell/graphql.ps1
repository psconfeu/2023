## Sample APIs - https://github.com/graphql-kit/graphql-apis

# ================ Simple Query ==========================
$query = @"
query Launches {
    launches {
      id
      mission_name
      details
    }
}
"@

$body = @{
    "query" = $query
} | ConvertTo-Json -Depth 100 -Compress

$params = @{
  "URI" = "https://spacex-production.up.railway.app"
  "Method" = "POST"
  "Headers" = @{                                 
    'Content-Type' = 'application/json';
    'Accept'       = 'application/json';
  }
  "Body" = $body
}

$response = Invoke-WebRequest @params | ConvertFrom-Json

$response.data.launches

# ===================== Simple Query w/ Inline Variables ============================

$limit=1

$query = @"
query Launches {
    launches(limit: $limit) {
      id
      mission_name
      mission_id
      details
    }
}
"@

$params.Body = @{
    "query" = $query
} | ConvertTo-Json -Depth 100 -Compress

$response = Invoke-WebRequest @params | ConvertFrom-Json

$response.data.launches

# ===================== External Variables ===============================

# Define Query
$query = @'
query Launches($limit: Int) {
    launches(limit: $limit) {
      id
      mission_name
      mission_id
      details
    }
  }
'@

# Put it all together
$params.Body = @{
    "query" = $query
    "variables" = @{
      "limit" = 5
    }
} | ConvertTo-Json -Depth 100 -Compress

$response = Invoke-WebRequest @params | ConvertFrom-Json

$response.data.launches


# But this all gets messy when using real world queries that aren't returning one or two things

# ================ Messy Code Query ==========================
$query = @'
query Launches($limit: Int) {
  launches(limit: $limit) {
    id
    mission_name
    mission_id
    details
    launch_date_local
    launch_date_unix
    launch_date_utc
    launch_site {
      site_id
      site_name
      site_name_long
    }
    rocket {
      rocket {
        id
        name
        type
      }
    }
    launch_success
    links {
      wikipedia
      video_link
      reddit_launch
      reddit_recovery
      presskit
    }
  }
}
'@

$params.Body = @{
    "query" = $query
    "variables" = @{
      "limit" = 1
    }
} | ConvertTo-Json -Depth 100 -Compress


$response = Invoke-WebRequest @params | ConvertFrom-Json

$response.data.launches

# =========================================
# To keep our code somewhat clean, it's best to store queries in external .gql files

$query = Get-Content ./queries/launches.gql
$query = ([String]::Join(" ",($query.Split("`n")))).Trim()

# Put it all together
$params.Body = @{
    "query" = $query
    "variables" = @{
        "limit" = 1
    }
} | ConvertTo-Json -Depth 100 -Compress

$response = Invoke-WebRequest @params | ConvertFrom-Json

$response.data.launches

# Even better yet, put it in a function

function runGQL {
    param (
        [Parameter()]
        [String] $uri,
        [String] $query,
        [hashtable] $variables,
        [String] $returnFilter,
        [hashtable] $headers
    )

    $query = Get-Content ./queries/$query.gql
    $query = ([String]::Join(" ",($query.Split("`n")))).Trim()

    $body = @{
        "query" = $query
        "variables" = $variables
    } | ConvertTo-Json -Depth 100 -Compress
    
    $fparams = @{
        "Uri" = $uri
        "Method" = "POST"
        "Headers" = $headers
        "Body" = $body
    }
    $response = Invoke-WebRequest @fparams | ConvertFrom-Json
    if ($response.$returnFilter) { 
        return $response.$returnFilter
    } else {
        return $response
    }
}

$params = @{
    "uri" = $uri
    "headers" = $headers
    "query" = "launches"
    "variables" = @{
        "limit" = 1
    }
    "returnFilter" = "data"
}

$launches = runGQL @params

$launches

# Get rid of the return filter and use aliases inside the gql file as it provides more consistency

function runGQL {
    param (
        [Parameter()]
        [String] $uri,
        [String] $query,
        [hashtable] $variables,
        [hashtable] $headers
    )

    $query = Get-Content ./queries/$query.gql
    $query = ([String]::Join(" ",($query.Split("`n")))).Trim()

    $body = @{
        "query" = $query
        "variables" = $variables
    } | ConvertTo-Json -Depth 100 -Compress
    
    $fparams = @{
        "Uri" = $uri
        "Method" = "POST"
        "Headers" = $headers
        "Body" = $body
    }
    $response = Invoke-WebRequest @fparams | ConvertFrom-Json
    return $response.data.myalias
}

$params = @{
    "uri" = $uri
    "headers" = $headers
    "query" = "launcheswithalias"
    "variables" = @{
        "limit" = 2
    }
}

$launches = runGQL @params
$launches

# The next logical question is, how do I form all these types and queries, what fields are available

# Use the docs if they exist, if not, use GQL Introspection

# Built in introspection to view queries
$params.query = "introspection-queries"

$response = runGQL @params

$response.queryType.fields

# find the return type of the query
$rocket = $response.queryType.fields | where {$_.name -eq 'rockets'}             
$rocket.type.ofType     

# Introspect the defined objects to get the fields

$params = @{
    "uri" = $uri
    "headers" = $headers
    "query" = "introspection-types"
    "variables" = $variables
}

$response = runGQL @params
$response.types

$response.types | where {$_.name -eq 'Rocket'} | select fields

# Or, use GraphiQL :) https://github.com/graphql/graphiql

# Fun project I've been working on - GraphQL-PowerShell

Import-module ./graphql-powershell/powershell-graphql-interface -Force

$params = @{
    "Name" = "SpaceX"
    "Uri" = "https://spacex-production.up.railway.app"
    "Headers" = @{
        'Content-Type' = 'application/json';
        'Accept'       = 'application/json';
    }
    "Depth" = 3
}

Connect-graphqlapi @params -Verbose

Get-Command -Module SpaceX

Get-SpaceXLaunches -Verbose

Get-Help Get-SpaceXLaunches

Get-SpaceXLaunches -Properties root.id, root.links.video_link -limit 2 -Verbose

Get-SpaceXLaunch -id 5eb87cd9ffd86e000604b32a -Verbose

# Barcelona Transit
$params.Name = "Barcelona"
$params.Uri = "https://barcelona-urban-mobility-graphql-api.netlify.app/graphql"
$params.Depth = 4
Connect-graphqlapi @params -Verbose

Get-Command -Module Barcelona

Get-BarcelonaBikeStations


