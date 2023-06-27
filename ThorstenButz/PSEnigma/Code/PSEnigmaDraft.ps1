###################
## PSEnigma, Draft
## 23-06-30
###################

#region STEP 1: Functions
function str2num ([char[]] $text) {
    foreach ($letter in $text) {
        [byte] [char] $letter - 65
    }
}
function rotate {    
    Param (        
        [array] $in,                
        [int] $offset, 
        [bool] $mimicDeque = $true
    )
    Process {
        if ($mimicDeque) { $offset = - $offset }        
        if ($offset -lt 1) { 
            $offset = $offset + $in.count
        }    

        for ($i = 1; $i -le $offset; $i++) { 
            $first, $rest = $in
            $in = $rest += $first
        }
        $in
    }                    
}   

function groupify {
    param ( 
        [Parameter(ValueFromPipeline)]        
        [string] $text,
        [int] $chunksize = 5,
        [switch] $wordmode
    )
    process {    
        Write-Verbose -Message "String length: $($text.length) characters" 
        if ($wordmode) {
            #$newStr = $text -replace '(?:[^ ]* ){5}[^ ]* ', "$&`n"
            $newStr = $text -replace "(?:[^ ]* ){$($chunksize-1)}[^ ]* ", "$&`n"
            $newStr.TrimEnd("`n")
        } 
        else {
            $chunks = [regex]::Matches($text, ".{1,$chunksize}") | Select-Object -ExpandProperty Value
            for ($i = 0; $i -lt $chunks.Count; $i += $chunksize) {
                $chunks[$i..($i + $chunksize - 1)] -join " "            
            }
        }
    }
}

function deblur {
    param ( 
        [Parameter(ValueFromPipeline)]
        [string] $text      
    )
    process {            
        $text -replace 'X', ' ' -replace 'Q', 'CH' -replace 'J', '?'
    }
}

function blur {
    param ( 
        [Parameter(ValueFromPipeline)]
        [ValidateLength(0, 250)]
        [ValidatePattern('^[A-Za-zÄÖÜäöü\s?:.]+$')]        
        [string] $text        
    )
    process { 
        $text.ToUpper() -split '\r?\n' -join ' ' -replace '\s+', ' ' -replace '[^\p{L}\s\?]' -replace 'Ä', 'AE' -replace 'Ö', 'OE' -replace 'Ü', 'UE' -replace ' ', 'X' -replace 'CH', 'Q' -replace '\?', 'J'        
    }
}
#endregion STEP 1 : Functions


#region STEP 2: Predefined characteristics
## Rotors and wiring (Walzen)
## https://en.wikipedia.org/wiki/Enigma_rotor_details
## https://de.wikipedia.org/wiki/Enigma-Rotors

[string[]] $rotors_r = # Wiring schema: rotors (Walzen) right side 
'EKMFLGDQVZNTOWYHXUSPAIBRCJ', # I    (Enigma 1, 1930)
'AJDKSIRUXBLHWTMCQGZNPYFVOE', # II   (Enigma 1, 1930)
'BDFHJLCPRTXVZNYEIWGAKMUSQO', # III  (Enigma 1, 1930)
'ESOVPZJAYQUIRHXLNFTGKDCMWB', # IV   (Enigma M3/Heer, 1938)
'VZBRGITYUPSDNHLXAWMJQOFECK', # V    (Enigma M3/Heer, 1938)
'JPGVOUMFYQBENHZRDKASXLICTW', # VI   (Enigma M3/M4, 1939)    // future use
'NZJHGRCXMYSWBOUFAIVLPEKQDT', # VII  (Enigma M3/M4, 1939)    // future use
'FKQHTLXOCBJSPDZRAMEWNIUYGV'  # VIII (Enigma M3/M4, 1939)    // future use

## Reflectors (Umkehrwalzen)
[string[]] $reflectors = 
'EJMZALYXVBWFCRQUONTSPIKHGD', # Reflector A 
'YRUHQSLDPXNGOKMIEBFZCWVJAT', # Reflector B 
'FVPJIAOYEDRZXWGCTKUQSBNMHL'  # Reflector C 

## Turnover notch positions (Übertragskerben)
$notchPositions = "Q E V J Z ZM ZM ZM"

## Converting letters into numbers 
[System.Collections.ArrayList] $alRotors_r = @()
foreach ($walze in $rotors_r) { [void] $alRotors_r.Add((str2num $walze)) }

[System.Collections.ArrayList] $alReflectors = @()
foreach ($reflector in $reflectors) { [void] $alReflectors.Add((str2num $reflector)) }

[System.Collections.ArrayList] $alNotchPositions = @()
foreach ($notches in $notchPositions.Split()) { [void] $alNotchPositions.Add((str2num $notches)) }

## The wiring on the left side of the rotors follows the alphabet (A-Z)
[System.Collections.ArrayList] $alRotors_l = 0..25

#endregion 2 STEP 2

#region STEP 3: Classes
class Rotor {
    ## Class properties
    $no
    $message_key
    $ring_pos
    $offset            # Debugging
    $wiring_l
    $wiring_l_letters  # Debugging
    $wiring_r
    $wiring_r_letters  # Debugging
    $notches
    $notches_letters   # Debugging                
    $turnover_pos

    ## Class constructor
    Rotor($no, $message_key, $ring_pos) {
        $this.no = $no  # Rotor 1 =>  $rotor_r[0]
        $this.message_key = $message_key
        $this.ring_pos = $ring_pos       
        $this.setup() 
    }

    ## Class methods
    [void]setup() {        
        $this.offset = $this.ring_pos - $this.message_key                
        $this.wiring_l = rotate -in $script:alRotors_l -offset $this.offset
        $this.wiring_r = rotate -in $script:alRotors_r[$this.no-1] -offset $this.offset
        
        $this.notches = @()
        $this.notches_letters = @()
        foreach ($k in $script:alNotchPositions[$this.no-1] ) {
            $this.notches_letters += [char] $(((($k - $this.ring_pos)+26) % 26) + 65)      # Debugging
            $this.notches += (($k - $this.ring_pos)+26) % 26   # Mind the gap: positiv modulo !
            $this.turnover_pos = $this.turnover()
            $this.turnover_pos = $this.turnover() 
        } 

        ## Debugging
        $this.wiring_l_letters = $(foreach ($number in $this.wiring_l ) { [char] ($number + 65)}) -join ''
        $this.wiring_r_letters = $(foreach ($number in $this.wiring_r ) { [char] ($number + 65)}) -join ''        
    }

    [void]click() {
        $this.wiring_l = rotate -in $this.wiring_l -offset -1
        $this.wiring_r = rotate -in $this.wiring_r -offset -1        
        
        ## Debugging
        $this.wiring_l_letters = $(foreach ($number in $this.wiring_l ) { [char] ($number + 65)}) -join ''
        $this.wiring_r_letters = $(foreach ($number in $this.wiring_r ) { [char] ($number + 65)}) -join ''        
        $this.turnover_pos = $this.turnover()         
    }
    
    ## Debugging
    [bool]turnover() {    
        if ($this.wiring_l[0] -in $this.notches) {return $true} else { return $false }        
    } 
}

<#  Test [Rotor]
$testRotor = [Rotor]::new(1,0,0)
$testRotor = [Rotor]::new(2,25,25)
$testRotor = [Rotor]::new(3,19,4)
$testRotor.click()
$testRotor.click()
$testRotor.turnover()
$testRotor
#>

 
class Enigma {
    ## Class properties
    [Array] $rotors
    [Array] $reflector
    [Hashtable] $plugboard = @{}
    $alReflectors = $alReflectors

    ## Class constructor
    Enigma(){}

    ## Class method(s)    
    ## Example: $myEnigma.setup(2, (2,4,5), "BLA", (2,21,12), "AV BS CG DL FU HZ IN KM OW RX")   
    setup($reflector_sel,$wheel_order,$message_key,$ring_pos,$plugboard_config) {
        
        # $reflector_sel: Which reflector (Umkehrwalze) was selected => 1,2,3
        $this.reflector = $this.alReflectors[$reflector_sel-1] 
        
        ## Wheel order (Walzenlage): 3 wheels from the wheel set and their position (left,middle,right/fast)        
        foreach ($i in 0..2) {
            ## Wert 1: Walzennummer 1 bis 8
            $currentWheel = $wheel_order[$i]    ## -1 bereits in Walze abgezogen
            
            ## Wert 2: Wheel position: from letter to number
            $wheelpos = [byte] [char] $message_key[$i] - 65 

            ## Wert 3: Ring setting (Ringposition) as number 
            $ringpos = $ring_pos[$i] - 1   ##  Mind the gap!
            $this.rotors += [Rotor]::new($currentWheel,$wheelpos,$ringpos)                                        
        }


        ##  Convert plugboard configuration into a hashtable
        foreach ($pair in $plugboard_config.Split()) {        
            $a = [byte][char]$pair[0]-65
            $b = [byte][char]$pair[1]-65    
            
            $this.plugboard[$a]=$b
            $this.plugboard[$b]=$a        
        }
    }
    
    [void] rotate(){
        $leftWheel, $centerWheel, $rightWheel = $this.rotors    
        
        ## The enigma anomaly: 
        ## https://www.cryptomuseum.com/crypto/enigma/working.htm#double
        ## https://de.wikipedia.org/wiki/Enigma_(Maschine)#Anomalie
        if ($centerWheel.turnover()) {
            $centerWheel.click()  ## Anomaly 
            $leftWheel.click()
        }
        elseif ($rightWheel.turnover()) {
            $centerWheel.click()
        }
        $rightWheel.click()
    }
}
<# Testing [Enigma]
$testEnigma = [Enigma]::new()
$testEnigma.setup(2, (2,4,5), "BLA", (2,21,12), "AV BS CG DL FU HZ IN KM OW RX")
#>

#endregion STEP 3

#region STEP 4: Translate
function translate {
    param (
        [string] $text = 'ABC',
        [Enigma] $e 
    )
    $text = $text.ToUpper()    
    $u_text = @()

    foreach ($c in [char[]] $text) {

        $c = ([byte]$c - 65)                  
        if ($c -lt 0 -or $c -gt 25) { continue }        
        $e.rotate()
        
        ## Plugboard (at the beginning)
        $c = if ($e.plugboard[$c] -ne $null) { $e.plugboard[$c] } else { $c } # Mind the "0"!
        
        ## Iterate in reverse order: right to left
        foreach ($i in ($e.rotors.count-1)..0) {              
            $w = $e.rotors[$i]        ## Current wheel
            $c = $w.wiring_r[$c]          
            $c = $w.wiring_l.IndexOf($c)         
        }

        ## Reflector
        $c = $e.reflector[$c]        

        # Iterate (on the way back: left to right)
        foreach ($i in 0..($e.rotors.count-1)) {
            $w = $e.rotors[$i]            
            $c = $w.wiring_l[$c]        
            $c = $w.wiring_r.IndexOf($c)        
        }
        
        ## Plugboard (at the ende)
        $c = if ($e.plugboard[$c] -ne $null) { $e.plugboard[$c] } else { $c } # Mind the "0" again!              
        
        ## Save the result
        $u_text += [char]($c + 65)
    } 
    ## Return the result
    $u_text -join ''
}
#endregion STEP 4

Clear-Host
## USAGE
@'
Basic Usage (see example below)
 - Create an Enigma-object
 - Call the setup() method configure the machine 
 - Translate $text. You can also encrypt/decrypt with the same settings (self-reciprocal).



## Example 1: Encrypt
$testEnigma = [Enigma]::new()
$testEnigma.setup(2, (5,2,4),'CZK', (17,09,02), 'KT AJ IV UR NY HZ GD XF PB CQ')
translate -text 'HELLOWORLD' -e $testEnigma  
'@ 

@'
## Example 2: Decrypt
$testEnigma = [Enigma]::new()
$testEnigma.setup(2, (5,2,4), 'CZK', (17,09,02), 'KT AJ IV UR NY HZ GD XF PB CQ')
translate -text 'GVPPSAPOKP' -e $testEnigma 
'@  | Write-Host -ForegroundColor Green
