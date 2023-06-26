function Get-AvailableCharactersRegex {
    (Get-AvailableCharacters) -join '|'
}
