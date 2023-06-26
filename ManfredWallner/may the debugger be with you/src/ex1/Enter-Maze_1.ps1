$ErrorActionPreference = 'Stop'

function Get-AvailableCharacters {
    @('Dipper', 'Mabel', 'Wendy', 'Stan', 'Robbie', 'Waddles', 'Ford', 'Gideon', 'Bill')
}

function Get-AvailableCharactersRegex {
    (Get-AvailableCharacters) -join '|'
}

$minPlayers = 1
$maxPlayers = (Get-AvailableCharacters).Count

do {
    $playerCount = Read-Host "how many players dare to enter the maze? ($minPlayers - $maxPlayers)"
} while (1..$maxPlayers -notcontains $playerCount)

$players = @()
1..$playerCount | ForEach-Object {
    $name = Read-Host " welcome player $_, what is your name?"
    $matcher = Get-AvailableCharactersRegex
    $name -match $matcher | Out-Null
    if (-Not $matches) {
        throw "YOU SHALL NOT PASS"
    }
    $players += $name
}
Write-Host "---------------------------------"

foreach ($player in $players) {
    Write-Host "'$player' enters the maze."
}
