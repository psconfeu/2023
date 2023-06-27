<# Load enigma file 
 . '.\HelperFunctions.ps1'
 . '.\PSEnigma.ps1'
#>

## Load enigma (quick'n dirty)
irm https://raw.githubusercontent.com/thorstenbutz/PSEnigma/main/PSEnigmaDraft.ps1 | iex
Clear-Host

## Create the message 
$text = @'
Prague is a wonderful city. 
Vysehrad castle offers a great view of the city.
You should try a walk or bike tour along the river vlatava.
'@

$message = $text | blur | groupify

## Encrypt and morse the code 
$testEnigma = [Enigma]::new()
$testEnigma.setup(2, (3,1,2), 'CZK', (21,6,23), 'AB KI CD EF GH XY VW JL MP QZ')
$encodedMessage = translate -text $message -e $testEnigma | groupify

## Decrypt the code
$testEnigma = [Enigma]::new()
$testEnigma.setup(2, (3,1,2), 'CZK', (21,6,23), 'AB KI CD EF GH XY VW JL MP QZ')
translate -text $encodedMessage -e $testEnigma | deblur | groupify -wordmode 
