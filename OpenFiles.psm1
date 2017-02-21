######################################## Function Get-OpenFiles ##############################################

Function Get-OpenFiles {

    <#
        .SYNOPSIS
            A function to grab the open files from a remote server using the "openfiles.exe" utility.
        .DESCRIPTION
            This will use "openfiles.exe" to grab the files which have an open session at time of execution and
            add the output to a file.
            This script has a relatively low footprint and simply adds to a file which will be processed later 
            using the Invoke-DeserialiseOpenFiles function. This function could be configured to run every minute
            on a file server using task scheduler for example.
        .PARAMETER CompName
            This is the name of the remote server you want this to run on. The default value is the local 
            computer. Multiple computers can be entered by using comma separated values.
        .PARAMETER FilteredDir
            This is a non-mandatory parameter which can be used to filter the sessions for a particular share
            rather than all open sessions on the entire server.
        .PARAMETER OutDirectory
            This is the folder where you want the output .csv file to reside. The default value is C:\temp
        .PARAMETER FilesOnly
            This is a switch. If used, it will run the filter to only include files rather than sessions to 
            open folders.
        .EXAMPLE
            Get-OpenFiles
            This will run with defaults - ie run openfiles.exe on the local computer and save the output to 
            c:\temp
        .EXAMPLE
            Get-OpenFiles -ComputerName FileServer01, FileServer02 -Folder HR\ -FilesOnly
            This will run on FileServer01 and FileServer02 and only output sessions which have "HR" in the full
            path (the assumption being that this will be to a HR directory). It will ignore sessions to only
            a folder and only output sessions which include a "." in the path (as a rule this will typically be 
            the dot in the file extension unless dots are used in the username).
        .NOTES
            AUTHOR: Edward Snow
            LASTEDIT: 20/02/2017 21:21
    #>

    param(
        [string[]]$CompName = $env:COMPUTERNAME,
        [string]$FilteredDir,
        [string]$OutDirectory = "c:\temp",
        [switch]$FilesOnly
    )

    $Global:ComputerName = $CompName
    $Global:Folder = $FilteredDir
    $Global:OutputDirectory = $OutDirectory
    $date = Get-Date -Format "dd/MM/yyyy HH:mm:ss"

    foreach ($Computer in $ComputerName) {

        $fileSessions = invoke-command -ComputerName $Computer {openfiles.exe /query /nh /fo CSV}

        if ($FilesOnly) {

            foreach ($fileSession in $fileSessions) {
    
                if (($fileSession -like "*$Folder*") -and ($fileSession -like "*.*") -or (($fileSession -notlike "*---*") -and ($fileSession -notlike "") -and ($fileSession -notlike "*Files opened remotely*") -and ($fileSession -notlike "*INFO: The system global*") -and ($fileSession -notlike "*See Openfiles /? for more*") -and ($filesession -notlike "*to be enabled to see local*"))) {

                    Add-Content -path $OutputDirectory\$Computer-OpenFiles.csv -Value "$fileSession,`"$date`""

                }

            }  

        }

        if (!$FilesOnly) {
    
            foreach ($fileSession in $fileSessions) {
    
                if (($fileSession -like "*$Folder*") -and ($fileSession -notlike "*---*") -and ($fileSession -notlike "") -and ($fileSession -notlike "*Files opened remotely*") -and ($fileSession -notlike "*INFO: The system global*") -and ($fileSession -notlike "*See Openfiles /? for more*") -and ($filesession -notlike "*to be enabled to see local*")) {

                    Add-Content -path $OutputDirectory\$Computer-OpenFiles.csv -Value "$fileSession,`"$date`""

                }

            }

        }

    }

}

################################## Function Invoke-DeserialiseOpenFiles ######################################

Function Invoke-DeserialiseOpenFiles {

    <#
        .SYNOPSIS
            This function will santise the output of a Get-OpenFiles output and enrich the data with additional
            values
        .DESCRIPTION
            The function will use the SessionID to remove duplicate values from the Get-OpenFiles output. If the 
            ImportAD parameter is used, then extra columns will added to the output. This requires the active 
            directory module for PowerShell and run from an account that has access to AD.
            Crucial to this operating as expected is the "Sort-Object sessionID" in the $import variable. Without
            this, the session IDs will be processed in random order and the logic which ensures that duplicate 
            sessions are ignored will not work as expected.
        .PARAMETER ImportAD
            A switch that if added, will attempt to import the AD module and add extra columns to the output.
            It uses the username which is output as part of the openfiles.exe command as a key to get the AD
            Object
        .PARAMETER ImportPath 
            The path to where the output of the Get-OpenFiles is. By default, this is the same value as the 
            Get-OpenFiles output. If this function is run stand alone, then you will need to include a value
            to the .csv file itself.
        .PARAMETER OutPath
            The path to where the output should go.            
        .EXAMPLE
            Invoke-DeserialiseOpenFiles
            This will use the default values for the parameters. It requires that the Get-OpenFiles function is 
            run in the same PowerShell session as the default values rely upon the global variables. It will
            process the output file of Get-OpenFiles, ignore any rows where the SessionID has already been 
            processed, and output to the default outpath location.
        .EXAMPLE
            Invoke-DeserialiseOpenFiles -importPath c:\users\eddys\desktop\someFile.csv -outpath c:\temp\allOfTheSessions.csv -importAD
            
            This command will import the someFile.csv, output to the allOfTheSessions.csv file and will attempt
            to add values from the ADUser object, using the active directory PowerShell module to the output
            csv file.
        .NOTES
            AUTHOR: Edward Snow
            LASTEDIT: 20/02/2017 22:04
    #>

    param(
    [switch]$importAD,
    [string]$importPath = "$OutputDirectory\$ComputerName-OpenFiles.csv",
    [string]$outPath = "$OutputDirectory\$ComputerName-FilesUsed.csv"
    )

    $import = Import-Csv -Header sessionID,Username,clientDevice,Path,timestamp -Path $importPath | Sort-Object sessionID
    $sessionID = ""

    if ($importAD) {

        import-module activedirectory
        #Add-Content -Path $outPath -Value "SessionID,Username,Email,FirstName,Lastname,Filepath,TimeAccessed"

        foreach ($line in $import) {

            $newSessionID = $line.sessionID

            if ($newSessionID -ne $sessionID) {

                $user = $line.username
                $query = get-aduser -Identity $user -Properties emailaddress
                $email = $query.emailaddress
                $fn = $query.givenname
                $sn = $query.surname
                $timestamp = $line.timestamp
                $file = $line.Path
                $sessionID = $line.sessionID
        
                add-content -Path $outPath -Value "$sessionID,$user,$email,$fn,$sn,$file,$timestamp"

            }

        }

    } else {

        #Add-Content -Path $outPath -Value "SessionID,Username,Filepath,TimeAccessed"

        foreach ($line in $import) {

            $newSessionID = $line.sessionID

            if ($newSessionID -ne $sessionID) {

                $user = $line.username
                $timestamp = $line.timestamp
                $file = $line.Path
                $sessionID = $line.sessionID
        
                add-content -Path $outPath -Value "$sessionID,$user,$file,$timestamp"

            }

        }

    }

}

################################### Function Invoke-SendMailAttachment #######################################

Function Invoke-SendMailAttachment {

    <#
        .SYNOPSIS
            This will e-mail an attachment to a specified recipient
        .DESCRIPTION
            This is a simple function which will e-mail an attachment to a specified recipient. 
        .PARAMETER smtpServer
            The server that will be used to relay the message.
        .PARAMETER smtpFrom
            From address to inject in the e-mail headers.            
        .PARAMETER smtpTo
            Address of the recipient.
        .PARAMETER messageSubject
            Text to appear in the message subject. It will add the current date to the subject.
        .PARAMETER AttachmentPath
            The path to the file you want to attach. The default is the outpath of the Invoke-DeserialiseOpenFiles
            output.
        .EXAMPLE
            Invoke-SendMailAttachment -smtpServer exch01.lab.net -smtpFrom reports@lab.net -smtpTo eddy.snow@lab.net -AttachmentPath c:\temp\allOfTheSessions.csv
            This will use the Exchange server exch01.lab.net to send an e-mail from reports@lab.net to 
            eddy.snow@lab.net with the file c:\temp\allOfTheSessions.csv attached to it.
        .NOTES
            AUTHOR: Edward Snow
            LASTEDIT: 19/04/2016 09:06
    #>

    param(
        [parameter(Mandatory=$true)][string]$smtpServer,
        [parameter(Mandatory=$true)][string]$smtpFrom,
        [parameter(Mandatory=$true)][string]$smtpTo,
        [parameter(Mandatory=$true)][string]$messageSubject = "Open Files Report - " + (get-date -Format "dd-MM-yyyy"),
        [parameter(Mandatory=$true)][string]$AttachmentPath = $outPath
    )

    $message = New-Object System.Net.Mail.MailMessage $smtpfrom, $smtpto
    $attachment = New-Object System.Net.Mail.Attachment($AttachmentPath)
    $message.Subject = $messageSubject
    $message.IsBodyHTML = $true   
    $message.Body = "Open Files on $ComputerName."
    $smtp = New-Object Net.Mail.SmtpClient($smtpServer)
    $message.Attachments.Add($attachment)

    $smtp.Send($message)
    $attachment.Dispose()

}
