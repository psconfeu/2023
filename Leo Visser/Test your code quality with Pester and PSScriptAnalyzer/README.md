# PSScriptAnalyzer and Pester
This repo shows how you can use PSScriptAnalyzer and Pester together to generate a test report.

## Usage
If you want to use this locally call the test.ps1 file. Here are the examples to use in this demo:

```
.\test.ps1
```
This will call the script in default settings, it will use the simple way of combinding PSScriptAnalyzer and Pester to give you an output in the host.

```
.\test.ps1 -Type advanced
```
This will use the more advanced way of combining PSScriptAnalyzer and Pester. It will now show in which files there are issues and what these issues are.

```
.\test.ps1 -Type advanced -TestLocation '.\src\exemptions\'
```
This will have the script test the exemptions folder in src instead and will give an succesfull tests due to the excemptions being inserted into the scripts.

```
.\test.ps1 -Type advanced -OutputResults   
```
This will use the more advanced way of combining PSScriptAnalyzer and Pester. It will generate a file called pssa.testresults.xml in the root of this folder. This file can be published in a pipeline to show the testresults.

## Pipeline
There is a pre-made azure devops pipeline available in the repository. You can take the azure-pipeline-pssa.yml file. It has no predefined trigger as the intended use case would be to use it as build validation for a certain branch.