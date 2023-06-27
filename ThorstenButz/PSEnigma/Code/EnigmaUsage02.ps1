<# Load enigma file 
. '.\HelperFunctions.ps1'
. '.\PSEnigma.ps1'

## Create the message 
$text = 'FOURTY TWO IS THE ANSWER TO THE ULTIMATE QUESTION OF LIFE THE UNIVERSE AND EVERYTHING'
$message = $text | blur | groupify

## Encrypt and morse the code 
$testEnigma = [Enigma]::new()
$testEnigma.setup(2, (3,1,2), 'PSH', (21,6,23), 'AB KI CD EF GH XY VW JL MP QZ')
$encodedMessage = translate -text $message -e $testEnigma | groupify 
#>

## Load enigma (quick'n dirty)
irm https://raw.githubusercontent.com/thorstenbutz/PSEnigma/main/PSEnigmaDraft.ps1 | iex
Clear-Host

$encodedMessage = @'
WKYKX MTXAN BFUFD DBTIL YYRQW
OZKCT DTZCS SUNNS HATWO OXZOG
KGGON UIFUG WJSAU ACSYI SYBAD
KBBIF UKHFL
'@
## Decrypt the code
$testEnigma = [Enigma]::new()
$testEnigma.setup(2, (3,1,2), '???', (21,6,23), 'AB KI CD EF GH XY VW JL MP QZ')
translate -text $encodedMessage -e $testEnigma | deblur | groupify -wordmode 
