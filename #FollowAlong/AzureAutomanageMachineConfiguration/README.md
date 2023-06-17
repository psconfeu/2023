# Azure Automanage Machine Configuration for large environments

Jan-Hendrik PETERS
Raimund ANDRÈE

You are on the verge of onboarding your on-premises systems to Azure Arc and plan to manage them using Azure Automanage Machine Configuration?
Or do you already have everything set up, but want an overview of what is possible beyond pre-made Machine Configuration templates?

This session has got you covered. Using the popular DSC blueprint from the DSC community, you will be introduced to a scalable and manageable way of creating machine configurations.

You are invited to follow along in this session to create and publish configurations for your own machines.

## Requirements to follow along without deploying anything

This is the basic setup which allows you to at least try everything locally.

- Install at least PowerShell 7.3.4
- Install [Visual Studio Code](https://code.visualstudio.com) or an alternative, capable editor
  - Recommended extensions: PowerShell, YAML (Red Hat)
- Install [Git](https://git-scm.org)
- If, and only if, you do not want to use Azure Repos later on (see below), please clone `https://github.com/dsccommunity/DscWorkshop.git` in a folder of your choice. For example:
  ```powershell
    mkdir ~/repos
    git clone https://github.com/dsccommunity/DscWorkshop.git ~/repos/dscworkshop
  ```

## Requirements to follow along without virtual machines

This adds all the build automation on Azure DevOps if you want, but does not assign policies to machines.

- Everything from [Basic requirements](./README.md#Requirements-to-follow-along-without-deploying-anything)
- Access to an Azure subscription
  - Permissions to create a storage account or upload to an existing storage account
  - Permissions to create and assign policies
- Access to an Azure DevOps organization (!)
  - Without org access, deploying Machine Configuration policies requires you to create a Service Connection called GC1
  >Caution: If billing is not configured and free limits have never been requested, you may need to configure: <https://learn.microsoft.com/en-us/azure/devops/pipelines/licensing/concurrent-jobs?view=azure-devops&tabs=ms-hosted#tabpanel_1_ms-hosted>
- In Azure Repos, import the GitHub repository: <https://github.com/dsccommunity/DscWorkshop.git>
- In your editor of choice, clone your new repository. For example:
  ```powershell
    mkdir ~/repos
    git clone https://yourname@dev.azure.com/yourOrg/yourProject/_git/yourRepo ~/repos/dscworkshop
  ```

## Requirements to fully follow along (including deploying virtual machines)

This spins up sample machines using AutomatedLab, the world's leading lab automation tool, to
manage using Azure. Machines are deployed to Azure.

- Everything from [advanced requirements](./README.md#Requirements-to-follow-along-without-virtual-machines)
- Install AutomatedLab from either the gallery or <https://github.com/automatedlab/automatedlab/releases>
- In an administrative PowerShell 7, run: `Install-LabAzureRequiredModule`
- Connect to Azure and select your subscription
  - `Connect-AzAccount -UseDevice`
  - `Set-AzContext -Subscription NAMEOFYOURSUBSCRIPTION`
- In an administrative PowerShell 7 located in your cloned repo's root directory, run: `& "./Lab Guest Configuration/10 Azure Guest Configuration Lab.ps1"`
  >Hint: The default region is set to West Europe. Feel free to change this to another supported region display name using the script's parameters.
- If the deployment fails during the validation because a SKU is not available, have a look at the available VM sizes!  
    Please check if a size is generally usable with Standard managed SSDs in one single Availablity Set behind a load balancer first.  
    `Get-LabAzureAvailableRoleSize -DisplayName 'West Europe' | where NumberOfCores -le 4 | ft Name, NumberOfCores`
- Grab a drink, wait for approximately 30 minutes, and then run: `& "./Lab Guest Configuration/20 Azure Guest Configuration Lab Customizations.ps1"`

## Requirements to fully follow along (existing virtual machines)

You do you! If you have machines in Arc that you would like to manage, you will need to adapt
the configuration data, but you're probably advanced enough.

- Everything from [advanced requirements](./README.md#Requirements-to-follow-along-without-virtual-machines)
- VM(s) to manage, either Arc or Azure VMs. You will need to adapt your configuration data.
