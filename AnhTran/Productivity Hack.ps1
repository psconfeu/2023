# I. SETUP

#1. Import related modules
Import-Module Microsoft.Graph.Users
Import-Module -Name Microsoft.Graph.Mail
Import-Module -Name Microsoft.Graph.Calendar

#2. Connect to Microsoft Graph using an interactive login prompt
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.Readwrite","Calendars.ReadWrite", "Mail.ReadWrite", "Mail.Send" ,"MailboxSettings.ReadWrite"


# II. LOGICS

#----------------------------------------------------------------------
## 1. EMAIL
    # 1.1. Create Categories/ Labels
    # 1.2. Create Inbox Folders
    # 1.3. Define the priority and snooze durations
    # 1.4. Creare rules
#----------------------------------------------------------------------

$userId = (Invoke-MgGraphRequest -Method GET https://graph.microsoft.com/v1.0/me).id

#Inbox#
$param_inbox = "Inbox"
$parentfolderid = (Get-MgUserMailFolder -UserId $userId -filter "displayName eq '$param_inbox'"  | Select-Object -ExpandProperty id)

# 1.1. Create Categories/ Labels:
$categories = @("project_user_experience","project_chargingstation","project_paymentgateway","project_others")
$colors= @("preset1","preset2","preset3","preset4") 
$folders= @("Immediate Action","Snooze 1 hour","Snooze to EOD","others")


#Method 1: Dont care the colors
foreach ($category in $categoriesname) {
    New-MgUserOutlookMasterCategory -UserId $userId -displayName $category
    Write-Verbose -Message "Create category $category" 
    Write-Output $category
}

#Method 2: Assign color to each category:
for ($i = 0; $i -lt $categories.Length; $i++) {
    $category = $categories[$i]
    $color = $colors[$i]
    Write-Host $category $color 
    New-MgUserOutlookMasterCategory -UserId $userId -displayName $category -color $color
}

#1.2. Create Inbox Folders: 
foreach ($folder in $folders) {
    New-MgUserMailFolder -UserId $userId -displayName $folder -ParentFolderId $parentfolderid 
    Write-Verbose -Message "Create folder $folder" 
    Write-Output $folder
} 

#1.3. Define the priority and snooze durations
# Priority:
Get-MgUserMailFolder -UserId $userId -Top 20
$immediate_action_folder = (Get-MgUserMailFolder -UserId $userId -filter "displayName eq 'Immediate Action'"  | Select-Object -ExpandProperty id)
$snooze_1_hr_folder = (Get-MgUserMailFolder -UserId $userId -filter "displayName eq 'Snooze 1 hour'"  | Select-Object -ExpandProperty id)
$snooze_to_eod_folder = (Get-MgUserMailFolder -UserId $userId -filter "displayName eq 'Snooze to EOD'"  | Select-Object -ExpandProperty id)
$others = (Get-MgUserMailFolder -UserId $userId -filter "displayName eq 'others'"  | Select-Object -ExpandProperty id)

#Identity:
$Emails = Get-MgUserMessage -UserId $userId -Property  "subject,bodyPreview,uniqueBody" -Top 100 

#1.4. Creare rules:
#Purposes of emails:
    #- Communicate effectively to make impact

#Effective Communication to Make the Impact:
    #- Clear Purpose and Structure
    #- Action Request/ Transformation
    #- Human touch (energy/segmentation)
     
# Indicators
    # Send From:
    # Keywords:
    # Subject:
    # Impact: important
    # Priority: urgent
#Actions:
    # Send to/ Fowardto:
    # cc/ bcc:
    # Structure:
    # mark: Impact, priority, categories, folders

#1.4.1. Action = Reply immediately if (Impact= important and Priority = urgent) or (priority = urgent)

# 1.4.1.1. Create Rule
$params_rule = @{
	displayName = "Immediate Action"
	sequence = 2
	isEnabled = $true
    Conditions = @{
        AnyOf = @(
            @{
                SenderContains = @(
                    "boss@gmail.com"
                )
            },
            @{
                RecipientContains = @(
                    "boss@gmail.com"
                )
            },
            @{
                BodyOrSubjectContains = @(
                    "Urgent",
                    "Immediate Action",
                    "Urgency" 
                )
            },
            @{
                importance = "High"
            }
        )
    }
    actions = @{
        forwardAsAttachmentTo = @(
            @{
                EmailAddress = @{
                    Address = "boss@gmail.com"
                }
            }
        )
        MarkImportance = "High"
        moveToFolder = $immediate_action_folder
        stopProcessingRules = $true
    }
}

New-MgUserMailFolderMessageRule -UserId $userId -MailFolderId $parentfolderid -BodyParameter ($params_rule | ConvertTo-Json -Depth 4)

# 1.4.1.2 Create Draft Mail
$param_content = @{
	comment = @"
Dear Boss,

Thank you for your email. Here is the solution: 

- Impact: [Impact]
- Reason: [Reason]

I am happy to discuss further. Feel free to let me know if there is any concern. 

Regards,
[Your Name]
"@

	} 


# Draft the reply message

$folder_list = (Get-MgUserMailFolderMessage -UserId $userId -MailFolderId $immediate_action_folder | Select-Object -ExpandProperty id)

foreach ($message_id in $folder_list) {
    $craft_message= New-MgUserMessageReply -UserId $userId -MessageId $message_id -BodyParameter $param_content
    Write-Verbose -Message "Create draft message" 
    Write-Output $param_content.comment
}

# Similarly, you can create the snooze folder with specifying the rules based on your own preference.

#1.4.2. Action = snooze 1 hour if Impact= important and Priority = not-urgent

#1.4.3. Action = snooze to end of day if Impact= non-important and Priority = not-urgent


#----------------------------------------------------------------------
## 2. CALENDAR
    #2.1: Create Calendars
    #2.2: Set up time to check snooze messages
    #2.3: Attach the notes
    #2.4: Reminder for Birthdays
    # this is not to auto accept/reject/maybe actions
#----------------------------------------------------------------------

#2.1: Create Calendars:
$calendar_names = @("Marketing", "Finance","Training","Personal Appointment","Team-Birthdays")

Foreach ($calendar_name in $calendar_names) {  
    New-MgUserCalendar -UserId $userId -Name $calendar_name
} 

#2.2: Set up the meeting based on the input from the email, meeting minutes:
# Check snooze 1 hour/ Personal Appointment folder - review emails at 2pm daily:

$calendarId = (Get-MgUserCalendar -UserId $userId -filter "Name eq 'Personal Appointment'"  | Select-Object -ExpandProperty id)

$date = Get-Date -Hour 14 -Minute 0 -Second 0

$review_mail = @{
	subject = "Check Important Messages"
	body = @{
		contentType = "HTML"
		content = "Those are important but not urgent events"
	}
	start = @{
		dateTime = $date.AddMinutes(0).ToString("yyyy-MM-ddTHH:mm:ss")
		timeZone = "Pacific Standard Time"
	}
	end = @{
		dateTime = $date.AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ss")
		timeZone = "Pacific Standard Time"
	}
	attendees = @(
		@{
			emailAddress = @{
				address = "your email"
			}
			type = "required"
		}
	)
	allowNewTimeProposals = $true
}

New-MgUserCalendarEvent -UserId $userId -CalendarId $calendarId -BodyParameter $review_mail

#2.3: Attach the notes

function New-Note {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$filter,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$content
    )
    #Retrieve the event
    $eventId = (Get-MgUserEvent -UserId $userId -Filter "startswith(subject, '$filter')" | Select-Object -ExpandProperty id)

    #Insert links/texts
    $params = @{
        body = @{
            contentType = "HTML"
            content = $content
    }
}

    #Update events
    Update-MgUserEvent -UserId $userId -EventId $eventId -BodyParameter $params
}

function Add-Note {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$filter,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$content
    )
    #Retrieve the event
    $eventId = (Get-MgUserEvent -UserId $userId -Filter "startswith(subject, '$filter')" | Select-Object -ExpandProperty id)

    #Insert links/texts
    $params = @{
        body = @{
            contentType = "HTML"
            content = (Get-MgUserEvent -UserId $userId -Filter "startswith(subject, '$filter')").Body.Content + $content
    }
}

    #Update events
    Update-MgUserEvent -UserId $userId -EventId $eventId -BodyParameter $params
}

#2.4: Reminder for Birthdays
# Set the birthdays
$birthdays = @{
    "Alice" = "2023-01-01" 
    "Bob" = "2023-02-14"
    "Charlie" = "2023-07-27"
}

# Create the reminders
#Birthday Calendar
$calendarId = (Get-MgUserCalendar -UserId $userId -filter "Name eq 'Team-Birthdays'"  | Select-Object -ExpandProperty id)

foreach ($birthday in $birthdays.GetEnumerator()) {
    # Get the name and date of the birthday
    $name = $birthday.Key
    $date = $birthday.Value

    # Calculate the reminder date (1 day before the birthday)
    $reminderDate = [DateTime]::ParseExact($date, "yyyy-MM-dd", $null).AddDays(-1)

    # Create the event
    $birthday_reminder = @{
        Subject = "$name's Birthday Reminder"
        Body = @{
            ContentType = "HTML"
            Content = "Don't forget to wish $name a happy birthday tomorrow!"
        }
        Start = @{
            DateTime = $reminderDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
            TimeZone = "UTC"
        }
        End = @{
            DateTime = $reminderDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
            TimeZone = "UTC"
        }
        IsReminderOn = $true
        ReminderMinutesBeforeStart = 1440 # 24 hours
    }
    # Create the event in the team calendar
    New-MgUserCalendarEvent -UserId $userId -CalendarId $calendarId -BodyParameter $birthday_reminder

    # Print the response
    Write-Host "Event created for $name's birthday on $($reminderDate.ToString("yyyy-MM-dd")). Response:"
    $response | Format-List
}

