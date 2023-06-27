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
