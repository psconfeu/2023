## A
$request = Invoke-RestMethod -Uri 'http://api.open-notify.org/astros.json'
$request.people

## B
function Get-PeopleSpace {
    param ($craft)
    $request = Invoke-RestMethod -Uri 'http://api.open-notify.org/astros.json'
    if ($craft) {
        $request.people | Where-Object -FilterScript { $_.craft -eq $craft}
    } 
    else {
        $request.people
    }
}

Get-PeopleSpace -craft ISS