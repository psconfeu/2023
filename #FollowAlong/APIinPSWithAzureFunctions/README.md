# Build an API with PowerShell & Azure Functions

Ben Reader

Most people who work with Azure Functions tend to build small tools that do small repeatable tasks.
In this session, we are going to take it a step further and build a single Azure function that can interact
with an Azure table as an example of building "Azure functions as APIs."

We will build the entire solution from scratch and focus on authentication, code design,
request interrogation, and hopefully learn a thing or two about how PowerShell makes API development fun AND easy!

## Pre Requirements - SUPER IMPORTANT!!!

I want to do this follow along the correct way - which is using docker / devContainers / code spaces etc, but we are at a conference and that will KILL the wifi.

So, in lieu of everyone bringing down the network, please make sure you have the following tools installed on your machine so that you can follow along with me.

- [Visual Studio Code.](https://code.visualstudio.com/download)

- [Azure Functions Extension for Visual Studio Code.](https://learn.microsoft.com/en-us/azure/azure-functions/functions-develop-vs-code?tabs=powershell#:~:text=supported%20platforms.-,Azure%20Functions%20extension,-.%20You%20can%20also)

- [The Azure Functions Core Tools version 2.x or later](https://learn.microsoft.com/en-us/azure/azure-functions/functions-develop-vs-code?tabs=powershell#:~:text=The-,Azure%20Functions%20Core%20Tools,-version%202.x). The Core Tools package is downloaded and installed automatically when you start the project locally. Core Tools include the entire Azure Functions runtime, so download and installation might take some time.

- [PowerShell 7.2 recommended.](https://learn.microsoft.com/en-us/azure/azure-functions/functions-develop-vs-code?tabs=powershell#:~:text=take%20some%20time.-,PowerShell%207.2,-recommended.%20For%20version) For version information, see PowerShell versions.

- [.NET 6.0 runtime.](https://dotnet.microsoft.com/download)

- [The PowerShell extension for Visual Studio Code.](https://learn.microsoft.com/en-us/azure/azure-functions/functions-develop-vs-code?tabs=powershell#:~:text=PowerShell%20extension%20for%20Visual%20Studio%20Code)

- Other important extensions

    - [Git Extension Pack](https://marketplace.visualstudio.com/items?itemName=donjayamanne.git-extension-pack)

    - [Thunder Client](ttps://marketplace.visualstudio.com/items?itemName=rangav.vscode-thunder-client)


If you have any questions before this session - please come and find me!!
