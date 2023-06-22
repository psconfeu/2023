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