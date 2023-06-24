Import-Module -Name "C:\PSCONF\Secrets\SDEAdmin"
Set-SDEDatabase -SQLServer PSDC -SQLDatabase SDE4711
Get-SDECertificate
Add-SDECertificate -Path "C:\temp\alice.cer"
Add-SDECertificate -Path "C:\temp\bob.cer" -DisplayName Bob
New-SDECredential -Name "AzureSecret" -Credential (Get-Credential) -Thumbprint 45B2786B2A81624F93174B87DA85381FE07978A1

# https://psdc.psconf.metabpa.org/api/45B2786B2A81624F93174B87DA85381FE07978A1/AzureSecret
