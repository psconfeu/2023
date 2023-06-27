###############################################
## ONE-TIME PAD: the perfect cipher
## https://en.wikipedia.org/wiki/One-time_pad
###############################################

[char]65
[char]90
$offset = 65

## Create a ONE-TIME-PAD
[string] $myRandomPad = [char[]] (Get-Random -InputObject (65..90) -Count 26) -join ''
$myRandomPad.Length

$letter = 'A'
$letter -match '^[A-Z]$'  ## Any number of times => '^[A-Z]+$'

function enryptLetter {
    param (
        [byte][char]$letter, 
        [string]$otp
    )
    $offset = 65    
    $otp[$letter - $offset]
}
enryptLetter -letter 'A' -otp $myRandomPad

function decryptLetter {
    param (
        [byte][char]$letter, 
        [string]$otp
    )
    $offset = 65            
    [char]($offset + $myRandomPad.IndexOf($letter))
}
decryptLetter -letter 'I' -otp $myRandomPad


$cipher = enryptLetter -letter 'T' -otp $myRandomPad
decryptLetter -letter $cipher -otp $myRandomPad