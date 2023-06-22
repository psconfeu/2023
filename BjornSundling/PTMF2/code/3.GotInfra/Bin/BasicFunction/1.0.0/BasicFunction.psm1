#region FruitAPI

function FruitAPI {
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseBOMForUnicodeEncodedFile", "")]
    param (
        [switch]$Icons,
        $Auth
    )
    
    if ($Icons) {
        @('🍎','🍌','🥝')
    }
    else {
        @('Apple','Banana','Kiwi')
    }
}
#endregion FruitAPI

#region Invoke-FruitAPI

function Invoke-FruitAPI {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
    [CmdletBinding()]
    param (
        $Secret = 'SuperSecretPassword',
        [switch]$Icons
    )

    $Auth = ConvertTo-SecureString -String $Secret -AsPlainText -Force

    # Find the bug!
    FruitAPI -Auth $Auth -Icons:$Icons
}
#endregion Invoke-FruitAPI

