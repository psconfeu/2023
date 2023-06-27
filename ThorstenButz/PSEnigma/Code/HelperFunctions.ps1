##########################
## HelperFunctions
## groupify, blur, deblur
##########################

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

return ## Stop here while dot sourcing

$test_string = @'
Das Oberkommando der Wehrmacht gibt bekannt: Aachen ist gerettet. 
Durch gebündelten Einsatz der Hilfskräfte konnte die Bedrohung abgewendet 
und die Rettung der Stadt gegen eins acht null null Uhr sichergestellt werden
'@   
$test_string.Length | Write-Host -ForegroundColor Yellow

blur $test_string  | groupify 
blur $test_string  | deblur | groupify -wordmode
