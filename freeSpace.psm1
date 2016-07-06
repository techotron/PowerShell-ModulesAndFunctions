<#
.Synopsis
   Gathers Disk Drive Available FreeSpace Percentage
.DESCRIPTION
    This function gathers information about HDDs and then reformats the output `
    to an easy to read output with the available FreeSpace percentage.
.EXAMPLE
   Get-FreeSpace localhost | ConvertTo-Html | Out-File C:\
#>
function Get-FreeSpace {
                        [CmdletBinding()]
                 Param ([Parameter(Mandatory=$false,
                        ValueFromPipelineByPropertyName=$true,
                        Position=0)]
                        $Computername )

        Begin { $Begin = Get-WmiObject Win32_LogicalDisk -computername $computername}
                        

    Process { $Process = $Begin | Where-Object { $_.DriveType -eq "3" } | Select-Object SystemName, 
            @{ Name = "Drive" ; Expression = { ( $_.DeviceID ) } },
            @{ Name = "Size (GB)" ; Expression = {"{0:N1}" -f( $_.Size / 1gb)}},
            @{ Name = "FreeSpace (GB)" ; Expression = {"{0:N1}" -f( $_.Freespace / 1gb ) } },
            @{ Name = "PercentFree" ; Expression = {"{0:P1}" -f( $_.FreeSpace / $_.Size ) } } }
                    
End { $Process | Format-Table -AutoSize }
}