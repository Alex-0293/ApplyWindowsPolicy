<#
    .SYNOPSIS
        ApplyWindowsPolicy
    .DESCRIPTION
        Apply windows policy.Change registry and save backup.
    .LINK
        https://github.com/Alex-0293/ApplyWindowsPolicy.git
    .COMPONENT
        AlexkUtils
    .NOTES
        AUTHOR  AlexK (1928311@tuta.io)
        CREATED 14.11.2020
        VER     1
        LANG    En
#>
Param (
    [Parameter( Mandatory = $false, Position = 0, HelpMessage = "Initialize global settings." )]
    [bool] $InitGlobal = $true,
    [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Initialize local settings." )]
    [bool] $InitLocal  = $true
)

$Global:ScriptInvocation = $MyInvocation
if ($env:AlexKFrameworkInitScript){
    . "$env:AlexKFrameworkInitScript" -MyScriptRoot (Split-Path $PSCommandPath -Parent) -InitGlobal $InitGlobal -InitLocal $InitLocal
} Else {
    Write-host "Environmental variable [AlexKFrameworkInitScript] does not exist!" -ForegroundColor Red
     exit 1
}
if ($LastExitCode) { exit 1 }
#######################################  Git  #######################################
$Global:gsGitMetaData.Commit  = $False
$Global:gsGitMetaData.Message = ""
$Global:gsGitMetaData.Branch  = "master"
#####################################################################################
# Error trap
trap {
    if (get-module -FullyQualifiedName AlexkUtils) {
        Get-ErrorReporting $_
        . "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
    }
    Else {
        Write-Host "[$($MyInvocation.MyCommand.path)] There is error before logging initialized. Error: $_" -ForegroundColor Red
    }
    exit 1
}
#################################  Mermaid diagram  #################################
<#
```mermaid

```
#>
################################# Script start here #################################






################################# Script end here ###################################
. "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
