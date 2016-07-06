<#
.Synopsis
    Lists the size of a directory by summing the recursive contents of the specified directory
.EXAMPLE
    Get-Directorysize -path \\servername\c$\users\
#>
function Get-DirectorySize {

param(
    [string]$path
)

    $dirs = (Get-ChildItem -Directory $path).fullname

     foreach ($dir in $dirs) {

        $colItems = (Get-ChildItem $dir -Recurse | measure-object -Property Length -sum)
        $size = "{0:N2}" -f ($colItems.sum / 1MB) + " MB"
        write-host "$dir =====  $size"

     }


}