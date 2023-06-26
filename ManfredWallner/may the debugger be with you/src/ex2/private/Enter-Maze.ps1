function Enter-Maze {

    $minPlayers = 1
    $maxPlayers = (Get-AvailableCharacters).Count

    do {
        $playerCount = Read-Host "how many players dare to enter the maze? ($minPlayers - $maxPlayers)"
    } while (1..$maxPlayers -cnotcontains $playerCount)

    $players = @()
    1..$playerCount | ForEach-Object {
        $players += Read-Host " welcome player $_, what is your name?" | Test-IsCharacterAllowed
    }
    Write-Host "---------------------------------"

    foreach ($player in $players) {
        Write-Host "'$player' enters the maze."
    }
    $players
}
