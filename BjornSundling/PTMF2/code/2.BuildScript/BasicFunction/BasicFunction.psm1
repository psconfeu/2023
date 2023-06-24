# import private functions
foreach ($file in (Get-ChildItem "$PSScriptRoot\private\*.ps1"))
{
	try {
		Write-Verbose "Importing $($file.FullName)"
		. $file.FullName
	}
	catch {
		Write-Error "Failed to import '$($file.FullName)'. $_"
	}
}

# import public functions
foreach ($file in (Get-ChildItem "$PSScriptRoot\public\*.ps1"))
{
	try {
		Write-Verbose "Importing $($file.FullName)"
		. $file.FullName
	}
	catch {
		Write-Error "Failed to import '$($file.FullName)'. $_"
	}
}
