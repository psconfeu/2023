
function Start-MazeLootGame {

    $lootItems = [System.Collections.Queue](Get-AvailableItems)
    $totalItems = $lootItems.Count

    $players = Enter-Maze

    $playerThreads = foreach ($player in $players) {
        Start-Looting $player $lootItems
    }

    while ($lootItems.Count -And ($playerThreads.State -ne 'Completed')) {
        Start-Sleep -Milliseconds 10
    }

    $playerData = Receive-Job $playerThreads -AutoRemoveJob -Wait

    $playerData = $playerData | Sort-Object -Property ItemCount -Descending

    $winner = $playerData | Select-Object -First 1
    Write-Host "$($winner.name) wins!"
    $collectedItems = ($playerData.ItemCount | Measure-Object -Sum).Sum
    Write-Host "there were a total of $totalItems items, $collectedItems have been collected."

    $playerData
}
