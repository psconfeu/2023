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
