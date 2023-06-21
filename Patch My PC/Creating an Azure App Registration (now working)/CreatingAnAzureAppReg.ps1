<#
    .DESCRIPTION
    Step by step guide on creating an azure app registration using Graph API
#>
Import-Module -Name Microsoft.Graph.Authentication
Import-Module -Name Microsoft.Graph.Identity.SignIns
Import-Module -Name Microsoft.Graph.Identity.DirectoryManagement
$AuthPermissions = 'AppRoleAssignment.ReadWrite.All','Application.Read.All'
$AppPermissions = 'DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','DeviceManagementRBAC.Read.All','DeviceManagementApps.ReadWrite.All','DeviceManagementServiceConfig.ReadWrite.All','GroupMember.Read.All'

#Region - 1 - Connect MgGraph
Write-Host "Connecting to Microsoft Graph API" -ForegroundColor Yellow
try{
    Connect-MgGraph
    Write-Host "Successfully connected to Microsoft Graph API" -ForegroundColor Green
    Disconnect-MgGraph
    Write-Host "Successfully disconnected to Microsoft Graph API" -ForegroundColor Green
}catch{    
    Write-Host $_.Exception.Message -Verbose -ForegroundColor Red
}
#EndRegion

#Region - 2 - Connect MgGraph with permissions
$permissions = "Application.ReadWrite.All"
Write-Host "Connecting to Microsoft Graph API with permissions: $permissions" -ForegroundColor Yellow
try{
    Connect-MgGraph -Scopes $permissions
    Write-Host "Successfully connected to Microsoft Graph API with permissions: $permissions" -ForegroundColor Green
    Disconnect-MgGraph
    Write-Host "Successfully disconnected to Microsoft Graph API" -ForegroundColor Green
}catch{    
    Write-Host $_.Exception.Message -Verbose -ForegroundColor Red
}
#EndRegion

#Region - 3 - Create Basic Azure App Registration
$DisplayName = "PSConfEU2023 - App Registration ({0})" -f (New-Guid).Guid
Write-Host "Connecting to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Yellow
try{
    Connect-MgGraph -Scopes $AuthPermissions
    Write-Host "Successfully connected to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Green

    $AppRegistration = New-MgApplication -DisplayName $DisplayName

    Disconnect-MgGraph
    Write-Host "Successfully disconnected to Microsoft Graph API" -ForegroundColor Green

}catch{    
    Write-Host $_.Exception.Message -Verbose -ForegroundColor Red
}
#EndRegion

#Region - 4 - Create Azure App Registration with permissions
$DisplayName = "PSConfEU2023 - App Registration ({0})" -f (New-Guid).Guid
$roles = @(
    @{
        #Microsoft Graph App ID
        "resourceAppId" = "00000003-0000-0000-c000-000000000000"
        "resourceAccess" = @(
            @{
                # DeviceManagementConfiguration.Read.All
                "id" = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
                "type" = "Role"
            },
            @{
                # DeviceManagementManagedDevices.Read.All
                "id" = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
                "type" = "Role"
            },
            @{
                # DeviceManagementRBAC.Read.All
                "id" = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"
                "type" = "Role"
            },
            @{
                # DeviceManagementApps.ReadWrite.All
                "id" = "78145de6-330d-4800-a6ce-494ff2d33d07"
                "type" = "Role"
            },
            @{
                # DeviceManagementServiceConfig.ReadWrite.All
                "id" = "5ac13192-7ace-4fcf-b828-1a26f28068ee"
                "type" = "Role"
            },
            @{
                # GroupMember.Read.All
                "id" = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
                "type" = "Role"
            }
        )
    }
)
Write-Host "Connecting to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Yellow
try{
    Connect-MgGraph -Scopes $AuthPermissions
    Write-Host "Successfully connected to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Green

    $AppRegistration = New-MgApplication -DisplayName $DisplayName -RequiredResourceAccess $roles

    Disconnect-MgGraph
    Write-Host "Successfully disconnected to Microsoft Graph API" -ForegroundColor Green

}catch{    
    Write-Host $_.Exception.Message -Verbose -ForegroundColor Red
}
#EndRegion

#Region - 5 - Create Azure App Registration with permissions & grant consent
$DisplayName = "PSConfEU2023 - App Registration ({0})" -f (New-Guid).Guid
$roles = @(
    @{
        #Microsoft Graph App ID
        "resourceAppId" = "00000003-0000-0000-c000-000000000000"
        "resourceAccess" = @(
            @{
                # DeviceManagementConfiguration.Read.All
                "id" = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
                "type" = "Role"
            },
            @{
                # DeviceManagementManagedDevices.Read.All
                "id" = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
                "type" = "Role"
            },
            @{
                # DeviceManagementRBAC.Read.All
                "id" = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"
                "type" = "Role"
            },
            @{
                # DeviceManagementApps.ReadWrite.All
                "id" = "78145de6-330d-4800-a6ce-494ff2d33d07"
                "type" = "Role"
            },
            @{
                # DeviceManagementServiceConfig.ReadWrite.All
                "id" = "5ac13192-7ace-4fcf-b828-1a26f28068ee"
                "type" = "Role"
            },
            @{
                # GroupMember.Read.All
                "id" = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
                "type" = "Role"
            }
        )
    }
)
Write-Host "Connecting to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Yellow
try{
    Connect-MgGraph -Scopes $AuthPermissions
    Write-Host "Successfully connected to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Green

    $AppRegistration = New-MgApplication -DisplayName $DisplayName -RequiredResourceAccess $roles
    $ServicePrincipal = New-MgServicePrincipal -AppId $AppRegistration.AppId
    $ApiServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
    
    
    foreach ($Permission in $AppPermissions) { 
        $AppRole = $ApiServicePrincipal.AppRoles.Where{ $_.Value -eq $Permission -and $_.AllowedMemberTypes -eq 'Application'}
        if ($null -eq $AppRole) { $continue }
    
    
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -PrincipalId $ServicePrincipal.Id -ResourceId $ApiServicePrincipal.Id -AppRoleId $AppRole.Id
    }

    Disconnect-MgGraph
    Write-Host "Successfully disconnected to Microsoft Graph API" -ForegroundColor Green

}catch{    
    Write-Host $_.Exception.Message -Verbose -ForegroundColor Red
}
#EndRegion

#Region - 6 - Create Azure App Registration with permissions, grant consent & create a secret
$DisplayName = "PSConfEU2023 - App Registration ({0})" -f (New-Guid).Guid
$roles = @(
    @{
        #Microsoft Graph App ID
        "resourceAppId" = "00000003-0000-0000-c000-000000000000"
        "resourceAccess" = @(
            @{
                # DeviceManagementConfiguration.Read.All
                "id" = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
                "type" = "Role"
            },
            @{
                # DeviceManagementManagedDevices.Read.All
                "id" = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
                "type" = "Role"
            },
            @{
                # DeviceManagementRBAC.Read.All
                "id" = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"
                "type" = "Role"
            },
            @{
                # DeviceManagementApps.ReadWrite.All
                "id" = "78145de6-330d-4800-a6ce-494ff2d33d07"
                "type" = "Role"
            },
            @{
                # DeviceManagementServiceConfig.ReadWrite.All
                "id" = "5ac13192-7ace-4fcf-b828-1a26f28068ee"
                "type" = "Role"
            },
            @{
                # GroupMember.Read.All
                "id" = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
                "type" = "Role"
            }
        )
    }
)
Write-Host "Connecting to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Yellow
try{
    Connect-MgGraph -Scopes $AuthPermissions
    Write-Host "Successfully connected to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Green

    $AppRegistration = New-MgApplication -DisplayName $DisplayName -RequiredResourceAccess $roles
    $ServicePrincipal = New-MgServicePrincipal -AppId $AppRegistration.AppId
    $ApiServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
    
    
    foreach ($Permission in $AppPermissions) { 
        $AppRole = $ApiServicePrincipal.AppRoles.Where{ $_.Value -eq $Permission -and $_.AllowedMemberTypes -eq 'Application'}
        if ($null -eq $AppRole) { $continue }
    
    
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -PrincipalId $ServicePrincipal.Id -ResourceId $ApiServicePrincipal.Id -AppRoleId $AppRole.Id
    }

    $EndDate = (Get-Date).AddMonths(6)
    $passwordCred = @{
        displayName = $AppRegistration.DisplayName
        endDateTime = $EndDate
    }

    $Secret = Add-MgApplicationPassword -ApplicationId $AppRegistration.Id -PasswordCredential $passwordCred

    Disconnect-MgGraph
    Write-Host "Successfully disconnected to Microsoft Graph API" -ForegroundColor Green

}catch{    
    Write-Host $_.Exception.Message -Verbose -ForegroundColor Red
}
#EndRegion

#Region - 7 - Putting it all together
$DisplayName = "PSConfEU2023 - App Registration ({0})" -f (New-Guid).Guid
$roles = @(
    @{
        #Microsoft Graph App ID
        "resourceAppId" = "00000003-0000-0000-c000-000000000000"
        "resourceAccess" = @(
            @{
                # DeviceManagementConfiguration.Read.All
                "id" = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
                "type" = "Role"
            },
            @{
                # DeviceManagementManagedDevices.Read.All
                "id" = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
                "type" = "Role"
            },
            @{
                # DeviceManagementRBAC.Read.All
                "id" = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"
                "type" = "Role"
            },
            @{
                # DeviceManagementApps.ReadWrite.All
                "id" = "78145de6-330d-4800-a6ce-494ff2d33d07"
                "type" = "Role"
            },
            @{
                # DeviceManagementServiceConfig.ReadWrite.All
                "id" = "5ac13192-7ace-4fcf-b828-1a26f28068ee"
                "type" = "Role"
            },
            @{
                # GroupMember.Read.All
                "id" = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
                "type" = "Role"
            }
        )
    }
)
Write-Host "Connecting to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Yellow
try{
    Connect-MgGraph -Scopes $AuthPermissions
    Write-Host "Successfully connected to Microsoft Graph API with permissions: $AuthPermissions" -ForegroundColor Green

    $OrgId = (Get-MgOrganization).Id
    $AppRegistration = New-MgApplication -DisplayName $DisplayName -RequiredResourceAccess $roles
    Write-Host "Successfully created new App Registration with name $($AppRegistration.DisplayName)" -ForegroundColor Green

    $ServicePrincipal = New-MgServicePrincipal -AppId $AppRegistration.AppId
    Write-Host "Successfully created new Service Principal for App Registration $($AppRegistration.DisplayName)" -ForegroundColor Green
    
    $ApiServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
    
    foreach ($Permission in $AppPermissions) { 
        $AppRole = $ApiServicePrincipal.AppRoles.Where{ $_.Value -eq $Permission -and $_.AllowedMemberTypes -eq 'Application'}
        if ($null -eq $AppRole) { $continue }    
    
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -PrincipalId $ServicePrincipal.Id -ResourceId $ApiServicePrincipal.Id -AppRoleId $AppRole.Id
    }
    Write-Host "Successfully created new Service Principal Role Assignment for Service Principal $($AppRegistration.DisplayName) with permissions: $AppPermissions" -ForegroundColor Green

    $EndDate = (Get-Date).AddMonths(6)
    $passwordCred = @{
        displayName = $AppRegistration.DisplayName
        endDateTime = $EndDate
    }

    $Secret = Add-MgApplicationPassword -ApplicationId $AppRegistration.Id -PasswordCredential $passwordCred
    Write-Host "Successfully created new client secret for App Registration $($AppRegistration.DisplayName)" -ForegroundColor Green

    $AppRegOutput = @{
        "AppId" = $AppRegistration.AppId
        "AppSecret" = $Secret.SecretText
        "TenantId" = $OrgId
    }

    $file = "$PWD\AppRegistration.json"
    if(Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
    New-Item -Path $file -ItemType File
    Add-content $file -Value ($AppRegOutput | ConvertTo-Json -Depth 100)

    Disconnect-MgGraph
    Write-Host "Successfully disconnected to Microsoft Graph API" -ForegroundColor Green

}catch{    
    Write-Host $_.Exception.Message -Verbose -ForegroundColor Red
}
#EndRegion