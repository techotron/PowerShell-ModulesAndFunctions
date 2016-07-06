<#
.Synopsis
    Runs an infinate loop to check the last log for a specified log file.
.DESCRIPTION
    The script runs as an infinate loop and checks the log file every 50ms for the latest line. `
    It can be run on a remote computer by using the UNC path to the logfile. End the loop with CTRL+C.
.EXAMPLE
    Get-livelogfile -file \\server1\logfile.log
#>
function get-livelogfile {

param(
    [string]$file,
    [string]$frequency
)

    if ($frequency -eq $null) {

        $Global:frequency = 50

    }

    #$logName = "system"

    for(;;) {

    #write-host "O" -NoNewline

    $readFile = cat $file -tail 1
    Start-Sleep -Milliseconds $frequency
    $newReadFile = cat $file -Tail 1

    if (!($readFile -eq $newReadFile)) {

        write-host $readFile -ForegroundColor Yellow

        } else {

            #Do Nothing

        }

    }

}


