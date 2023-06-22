# Building a PowerShell module for Bicep using C# - almost 1.000.000 downloads later

Co-session by Emanuel Palm & Simon Wåhlin

Our Bicep PowerShell module was released in January 2021 and is approaching 1 million downloads from the PowerShell Gallery. What started as few simple commands has grown into a Bicep authoring tool, but it was not without a few hurdles along the way.

In August of 2020, Microsoft released their first alpha version of Azure Bicep, a new domain-specific language for deploying Azure resources declaratively. We jumped on the bandwagon at first sight and in January of 2021, our friend Stefan Ivemo had grown tired of keeping his Bicep version up to date and also wanted to simplify building all templates in a repository. He wrote a few scripts that soon turned into a module that started to grow. Not long thereafter, we took a dependency on the actual Bicep project and imported their DLLs in PowerShell to be able to get a more native PowerShell experience and access the inner functions of Bicep. What worked well in the beginning, soon resulted in dependency conflicts with other modules, and later on even with PowerShell itself. This was solved by breaking out the Bicep dependencies onto a binary module, which in turn led to more hurdles.

This is the story about how a PowerShell module was born and evolved into a C# project, the lessons we learned and how it helped a group of friends improve their coding skills.
