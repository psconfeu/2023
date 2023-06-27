function Convert-OTPMessage {
    [CmdletBinding(DefaultParameterSetName = 'Enrypt')]
    [Alias('crytp')]
    param (        
        ## [ValidatePattern('^[A-Z]$')]  <= Case agnostic        
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Enrypt', Position = 0)]
        [ValidateScript({ $_ -cmatch '^[A-Z]$' })] ## Case sensitive        
        [char[]] $letters,
        
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Decrypt', Position = 0)]
        [ValidateScript({ $_ -cmatch '^[A-Z]$' })]
        [char[]] $encryptedLetters,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Decrypt', Position = 1)]
        [switch] $decrypt,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'Decrypt', Position = 2)]
        [string[]]$otp
    )            
    process {
        $offset = 65
        if ($decrypt) {                        
            foreach ($encryptedLetter in [byte[]]$encryptedLetters) {                    
                [PSCustomObject]@{                    
                    'decryptedLetters' = [char] ($otp[0].IndexOf($encryptedLetter) + 65)
                    'encryptedLetters' = [char] $encryptedLetter                    
                    'otp'              = $otp
                }     
            }                        
        }
        else {
            foreach ($letter in [byte[]]$letters) {    
                ## Generating a new random OTP for every letter provided    
                [string] $otp = [char[]] (Get-Random -InputObject (65..90) -Count 26) -join ''
                
                ## Substitue any given letter with the equivalent from the OTP        
                [PSCustomObject]@{
                    'letters'          = [char] $letter
                    'encryptedLetters' = $otp[$letter - $offset]
                    'otp'              = $otp
                }        
            }
        }
    }
}

## A
Convert-OTPMessage -letters 'WEATHERFORECAST' | Tee-Object -Variable message

## B
($message | Select-Object -Property 'encryptedLetters', 'otp' | 
  Convert-OTPMessage -decrypt).decryptedLetters -join ''

## C
crytp PSCONFEU | crytp -decrypt