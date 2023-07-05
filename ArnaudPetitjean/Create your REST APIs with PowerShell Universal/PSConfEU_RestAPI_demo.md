# REST API Demos

Show how to log in remotely

## GET Method
1. Show how to create an endpoint that returns "Hello World!"

1. Show how to create an endpoint that returns WhoamI.exe

1. Show how to edit the endpoint.ps1 directly or from VSCode and return the PSVersionTable
```
"C:\ProgramData\UniversalAutomation\Repository\.universal\endpoints.ps1"
"\\ws2022-1\c$\ProgramData\UniversalAutomation\Repository\.universal\endpoints.ps1"
```
4. Show that changing the Environment affects the Endpoint

5. Add a new endpoint to Get the Active Directory users from a particular OU
```PowerShell
New-PSUEndpoint -Url "/aduser" -Method @('GET') -Endpoint {
    $Properties = 'DistinguishedName', 'Name', 'Surname', 'SamAccountName', 'SID', 'Enabled', 'EmailAddress'
    Get-ADUser -Filter * -SearchBase 'OU=PSConfEU,DC=powershell,DC=lab' -Properties $Properties | 
       Select-Object -Property $Properties
}
```
## GET Method with parameters

1. Let's add a parameter to be able to get only one particular user
```PowerShell
New-PSUEndpoint -Url "/aduser/:samaccountname" -Method @('GET') -Endpoint {
    $Properties = 'DistinguishedName', 'Name', 'Surname', 'SamAccountName', 'SID', 'Enabled', 'EmailAddress'
    Get-ADUser -Identity $samaccountname -Properties $Properties | Select-Object -Property $Properties
}
```

1. Let's show another technique with query strings
```PowerShell
New-PSUEndpoint -Url "/aduser" -Method @('GET') -Endpoint {
    $Properties = 'DistinguishedName', 'Name', 'Surname', 'SamAccountName', 'SID', 'Enabled', 'EmailAddress'
    Get-ADUser -Identity $samaccountname -Properties $Properties | Select-Object -Property $Properties
}
```

1. For security reasons (and Best practices), it's best to create a Parameter with Param
```PowerShell
New-PSUEndpoint -Url "/aduser" -Method @('GET') -Endpoint {
    Param ([String]$SamAccountName)
    $Properties = 'DistinguishedName', 'Name', 'Surname', 'SamAccountName', 'SID', 'Enabled', 'EmailAddress'
    Get-ADUser -Identity $SamAccountName -Properties $Properties | Select-Object -Property $Properties
}
```

1. Show that using the browser to call the API you see the native Json return

1. Let's enhance our endpoint to add logic to return all the users if no samaccountname is specified
```PowerShell
New-PSUEndpoint -Url "/aduser" -Method @('GET') -Endpoint {
    Param ([String]$SamAccountName)

    $Properties = 'DistinguishedName', 'Name', 'Surname', 'SamAccountName', 'SID', 'Enabled', 'EmailAddress'
    if ($samaccountname) {
        Get-ADUser -Identity $samaccountname -Properties $Properties| Select-Object -Property $Properties
    } 
    else {
        Get-ADUser -Filter * -SearchBase 'OU=PSConfEU,DC=powershell,DC=lab' -Properties $Properties | 
           Select-Object -Property $Properties        
    }
}
```

## POST Method with parameters

1. Now it's time to try another method. POST will be useful to create something. So let create a user.
```Powershell
New-PSUEndpoint -Url "/aduser" -Method @('POST') -Endpoint {
Param (
    [String] $SamAccountName,
    [String] $Name,
    [String] $Surname
)
    $OU = 'OU=PSConfEU,DC=powershell,DC=lab'
    New-ADUser -SamAccountName $SamAccountName -Name $Name -Surname $Surname -Path $OU 
}
```

Let's give it a try to create a new user.

```Powershell
$body = @{
    SamAccountName = 'john.smith'
    Name    = 'Smith'
    Surname = 'John'
}

Invoke-RestMethod http://ws2022-1:5000/aduser -Method Post -Body $Body
```

The endpoint doesn't work because we are not using the right account to execute our action.
We have to create a new Environment and assign it to the Endpoint.
    1. First we have to create a variable to store the credential of the account that will run the environment
    2. Show how to create a secret variable 
    3. Create the environment (C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe)

But what if the endpoints fails?

So let's improve our API with returning our proper return code.
```Powershell
New-PSUEndpoint -Url "/aduser" -Method @('POST') -Endpoint {
    Param (
        [String] $SamAccountName,
        [String] $Name,
        [String] $Surname
    )
    $OU = 'OU=PSConfEU,DC=powershell,DC=lab'
    try {
        New-ADUser -SamAccountName $SamAccountName -Name $Name -Surname $Surname -Path $OU -ErrorAction Stop
    }
    catch {
        New-PSUApiResponse -StatusCode 501 -Body ($_.Exception.Message)
    }
} -ErrorAction "stop" -Environment "AD Administration"
```

## DELETE Method

Now it's time to add a method to delete a user
1. Implement the DELETE method
```PowerShell
New-PSUEndpoint -Url "/aduser" -Method @('DELETE') -Endpoint {
    Param (
        [String] $SamAccountName
    )
        Remove-ADUser -Identity $SamAccountName -Confirm:$false
} -Authentication -Role @('User') -Environment "AD_Operator_Env"
```
2. Call it : 
```PowerShell
Invoke-RestMethod -Uri "http://ws2022-1:5000/aduser?samaccountname=appmickaelle.jordan" -Method DELETE -Headers @{Authorization = 'bearer <TOKEN>'}
```

## PUT METHOD

It could be cool to modify a user object. Let's create a mean to set his email address.

```PowerShell
New-PSUEndpoint -Url "/aduser" -Method @('PUT') -Endpoint {
    Param (
        [String] $SamAccountName,
        [String] $email
    )
        Set-ADUser -Identity $SamAccountName -EmailAddress $email
} -Authentication -Role @('User') -Environment "AD_Operator_Env"
```
2. Call it : 
```PowerShell
Invoke-RestMethod -Uri "http://ws2022-1:5000/aduser?samaccountname=ppmickaelle.jordan&email=arnaud.petitjean@powershell.lab" -Method PUT -Headers @{Authorization = 'bearer <TOKEN>'}
```


## Securing an Endpoint

### With a token 

Set the role User to the endpoint API
1. Create an Identity for example `API_User` and assign it a User role.
2. Activate Authentication on the endpoint for the User role.
2. Copy the token of the user
3. Call the API : 
```PowerShell
Invoke-RestMethod -Uri "http://ws2022-1:5000/aduser" -Method POST -Body @{SamAccountName = 'mickael.jordan'; Name = 'Jordan' ; Surname = 'Mickael'} -Headers @{Authorization = 'bearer <API TOKEN>'} 
```
### With Active Directory

1. Go the menu Security/Authentication and click 'Add Authentication Method'. Select 'Windows' and enable it.
2. Call the API with the parameters : UseDefaultCredentials and AllowUnencryptedAuthentication 
```PowerShell
Invoke-RestMethod -Uri "http://ws2022-1:5000/aduser" -Method POST -Body @{SamAccountName = 'Qpmickaelle.jordan'; Name = 'QJordane' ; Surname = 'Mickaelle'} -AllowUnencryptedAuthentication -UseDefaultCredentials
```
3. We can create and assign a new role to an API
    Show how to create a role, assign it to an API
    Show that returning $false in the roles.ps1 file refuses access to the API

    We can add little bit more logic to authorize fined grained access.
```PowerShell
$SecureGroupSID = 'S-1-5-21-1391392885-4208853594-1076594993-1730'
$userGroupSids = @($User.Claims | Where-Object {$_.Type -eq 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid'}) | Select-Object -ExpandProperty Value

# Returns True if the user is assign to $userGroupSids 

$userGroupSids -contains $SecureGroupSID
```

## SWAGGER View

http:/ws2022-1:5000/swagger/index.html

1. Montrer que l'on peut appeler l'API directement depuis Swagger.

### Adding help to better display the API doc

1. Add a synopsis and the rest and show again the Swagger view
   Decorate the /aduser API with the following and refresh the Swagger view.

```PowerShell
<# 
.SYNOPSIS
Get a specific user or a collection of users.

.DESCRIPTION
Returns all the users if a user is not specified.

.PARAMETER SamAccountName
Enter the user's SamAccountName.
#>
```

## LOGGING

Show the log location : Platform menu / Logging

## Create an app to call our API


```PowerShell

    New-UDTypography -Text 'Users'

    New-UDForm -Content {
        New-UDRow -Columns {
            New-UDColumn -SmallSize 6 -LargeSize 6 -Content {
                New-UDTextbox -Id 'txtFirstName' -Label 'First Name' 
            }
            New-UDColumn -SmallSize 6 -LargeSize 6 -Content {
                New-UDTextbox -Id 'txtLastName' -Label 'Last Name'
            }
        }
        New-UDTextbox -Id 'txtAddress' -Label 'Address'
        New-UDRow -Columns {
            New-UDColumn -SmallSize 6 -LargeSize 6  -Content {
                New-UDTextbox -Id 'txtState' -Label 'State'
            }
            New-UDColumn -SmallSize 6 -LargeSize 6  -Content {
                New-UDTextbox -Id 'txtZipCode' -Label 'ZIP Code'
            }
        }
    } -OnSubmit {
        Show-UDToast -Message $EventData.txtFirstName
        Show-UDToast -Message $EventData.txtLastName
        $body = @{ Surname = $EventData.txtFirstName
            Name           = $EventData.txtLastName
            SamAcountName  = ('{0}.{1}' -f $EventData.txtFirstName, $EventData.txtLastName)
        }
        Invoke-RestMethod -Uri "http://localhost:5000/aduser" -Method POST -Body $body -Headers @{Authorization = 'bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiQVBJX1VzZXIiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9oYXNoIjoiOGMxNjZhNWItOGI4Zi00MTViLWFhOTYtNmM0YTM2MzkwNzRhIiwic3ViIjoiUG93ZXJTaGVsbFVuaXZlcnNhbCIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6IlVzZXIiLCJuYmYiOjE2ODcyMjA2NTAsImV4cCI6MTY5MjQwNDY0MCwiaXNzIjoiSXJvbm1hblNvZnR3YXJlIiwiYXVkIjoiUG93ZXJTaGVsbFVuaXZlcnNhbCJ9.VDw08UkXmpzsx0ePy4F_XZZhdI8ElzIMfsBA9DtI_bo' }
    }
```