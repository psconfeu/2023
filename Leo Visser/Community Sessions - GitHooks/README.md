# Go to .git\hooks there are many sample hook files there.

# Create pre-commit and pre-push file (without extensions)

# pre-commit START:

#!/bin/sh
pwsh.exe -c "Invoke-Pester .\get-info.tests.ps1"

# pre-commit STOP
# pre-push START:

#!/bin/sh
pwsh.exe -c "if((Invoke-Pester .\get-info.tests.ps1 -PassThru).Result -eq 'Failed') {throw 'tests no successfull'}"

# pre-push STOP

# make sure the folder contains a get-info.tests.ps1 which contains tests.
# when committing tests will run but not block
# when pushing tests will run and block if unsuccessfull

# If you want to add it to your repo create a .githooks folder in your repo and add the githooks from above in there.
# Then run this command (for everyone once)

git config --local core.hooksPath .githooks