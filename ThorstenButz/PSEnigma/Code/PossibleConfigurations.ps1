##############################################################
## Calculation of the plugboard pairing options with 10 pairs
## factorial 10 => 3628800
## Final result should be: 150.738.274.937.250
##############################################################

## A: Walzenlage / wheel order (selection of rotors, 3 out of 5)
$a = 5*4*3      # 60

## B: Ringstellung / ring settings
$b = 26*26      #  676

## C: Walzenstellung / wheel settings
$c = 26*25*26   #  16.900

## D: Steckerverbindungen mit 10 Paaren / plugboard pairing with 10 pairs
[bigint] $d = (26*25/2)*(24*23/2)*(22*21/2)*(20*19/2)*(18*17/2)*(16*15/2)*(14*13/2)*(12*11/2)*(10*9/2)*(8*7/2) / 3628800 # 150.738.274.937.250

## Possible configurations aka "Key Space"
$a * $b * $c * $d 
103.325.660.891.587.134.000.000 ## more than 103 sextillion different configurations

####################
## Fun with numbers
## https://www.thoughtco.com/zeros-in-million-billion-trillion-2312346
## https://en.wikipedia.org/wiki/Long_and_short_scales
####################

<## 

A "Sextillion" (German: "Trilliarde") is a number with 21 zeros aka 1^21 or 1e+21.

  1.000.000.000.000.000.000.000
103.325.660.891.587.134.000.000


one hundred three sextillion, 
three hundred twenty-five quintillion, 
six hundred sixty quadrillion, 
eight hundred ninety-one trillion, 
five hundred eighty-seven billion, 
one hundred thirty-four million

Einhundertdrei Trilliarden, 
dreihundertfünfundzwanzig Trillionen, 
sechshundertsechzig Billiarden, 
achthunderteinundachtzig Billionen, 
fünfhundertsiebenundachtzig Milliarden, 
einhundertvierunddreißig Millionen.

##>
