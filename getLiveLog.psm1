<#
.Synopsis
    Runs an infinate loop to check the last event log for the specified parameters.
.DESCRIPTION
    The script runs as an infinate loop and checks the specified event log every 100ms for the latest event. `
    It can be run on a remote computer by adding the computername parameter. End the loop with CTRL+C.
.EXAMPLE
    Get-livelog -logname application -computer server1
#>
function get-livelog {

param(
    [string]$logName,
    [string]$computer
)

    #$logName = "system"

    for(;;) {

    #write-host "O" -NoNewline

        foreach ($log in $logName) {

            $lastEvent = Get-EventLog -LogName $log -Newest 1 -ComputerName $computer
            $newIndex = $lastEvent.Index
        

            if (!($oldIndex -eq $newIndex)) {

                $lastEvent
                $oldIndex = $lastEvent.Index

            } else {

                #write-host $lastEvent

            }

        }

    start-sleep -Milliseconds 100

    }

}
