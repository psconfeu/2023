$env:appId = '' # app id
$env:tenant = '' # tenant id
$env:certPath = '' # certificate path
$env:certThumb = '' # certificate thumbprint
$env:Secret = '' # client secret
$env:usrEmail = ''  # user email
$env:passwd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('')) # base64 encoded password