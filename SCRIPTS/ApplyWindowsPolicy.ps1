<#
    .SYNOPSIS
        ApplyWindowsPolicy
    .DESCRIPTION
        Apply windows policy. Change registry and save backup.
    .COMPONENT
        AlexkUtils
    .LINK
        https://github.com/Alex-0293/ApplyWindowsPolicy.git
    .NOTES
        AUTHOR  AlexK (1928311@tuta.io)
        CREATED 14.11.20
        VER     1
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
$Global:gsGitMetaData.InitialCommit = $True
$Global:gsGitMetaData.Commit        = $True
$Global:gsGitMetaData.Message       = "[Add] Base functionality implemented"
$Global:gsGitMetaData.Branch        = "master"
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

$PolicyArray = @()

$PolicyPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "AddPrinterDrivers"
$Policy = [PSCustomObject]@{
    Id           = 14003
    Name         = "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = "1"
    CurrentValue = ""
    HostName     = "UserPC"
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "DontDisplayLastUserName"
$Policy = [PSCustomObject]@{
    Id           = 14009
    Name         = "Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = "1"
    CurrentValue = ""
    HostName     = "Srv1"
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "ScRemoveOption"
$Policy = [PSCustomObject]@{
    Id           = 14012
    Name         = "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = '1' # Lock workstation
    CurrentValue = ""
    HostName     = ""
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "RequireSecuritySignature"
$Policy = [PSCustomObject]@{
    Id           = 14013
    Name         = "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = '1'
    CurrentValue = ""
    HostName     = ""
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "RequireSecuritySignature"
$Policy = [PSCustomObject]@{
    Id           = 14017
    Name         = "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = '1'
    CurrentValue = ""
    HostName     = ""
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "EnableSecuritySignature"
$Policy = [PSCustomObject]@{
    Id           = 14018
    Name         = "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = '1'
    CurrentValue = ""
    HostName     = ""
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "DisableDomainCreds"
$Policy = [PSCustomObject]@{
    Id           = 14020
    Name         = "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = '1'
    CurrentValue = ""
    HostName     = ""
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "NTLMMinClientSec"
$Policy = [PSCustomObject]@{
    Id           = 14028
    Name         = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = '537395200'
    CurrentValue = ""
    HostName     = ""
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "NTLMMinServerSec"
$Policy = [PSCustomObject]@{
    Id           = 14029
    Name         = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = '537395200'
    CurrentValue = ""
    HostName     = ""
}
$PolicyArray += $Policy

$PolicyPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa".Replace("HKEY_LOCAL_MACHINE", "HKLM:")
$Property   = "RestrictAnonymous"
$Policy = [PSCustomObject]@{
    Id           = 14039
    Name         = "Ensure Null sessions are not allowed"
    Path         = $PolicyPath.trim()
    Property     = $Property
    DesiredValue = '1'
    CurrentValue = ""
    HostName     = ""
}
$PolicyArray += $Policy

foreach ( $Computer in $Global:Computers ) {
    $RuleSet = $PolicyArray | Where-Object { ($_.HostName -eq "") -or ($_.HostName -eq $Computer)}

    if ( $Computer -eq $env:COMPUTERNAME ) {
        $FilePath = "$ProjectRoot\$($Global:gsDATAFolder)\backup-$($env:COMPUTERNAME)-$(Get-date -format 'dd.MM.yy HH-mm-ss').reg"

        if ( $Global:BackupRegistry ){
            Add-ToLog -Message "Backing up, current registry settings." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
            foreach ( $Item in $RuleSet ){
                Export-RegistryToFile -FilePath $FilePath -Path $Item.Path -Property $Item.Property
            }
        }

        if ( Test-ElevatedRights ) {
            $RuleSet = $RuleSet | Where-Object { $_.CurrentValue -ne $_.DesiredValue }
            foreach ( $item in $RuleSet ){
                Add-ToLog -Message "Setting [$($Item.Path)] property [$($Item.Property)] to [$($Item.DesiredValue)]." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                try {
                    $item.CurrentValue = (Get-Item $Item.Path).GetValue($Item.Property)
                    if ( $item.CurrentValue -ne $Item.DesiredValue ){
                        Set-ItemProperty -Path $Item.Path -name $Item.Property -Value $Item.DesiredValue
                        Add-ToLog -Message "Successfully set." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                    }
                    Else {
                        Add-ToLog -Message "Values are equal." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                    }
                }
                Catch {
                    Add-ToLog -Message "Unable to set [$($Item.Path)] property [$($Item.Property)] to [$($Item.DesiredValue)] with error [$_]!" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
                }
            }
        }
        Else {
            $SB = {
                import-module -name "AlexkUtils" -force
                $RuleSet = import-csv -path """$([Environment]::ExpandEnvironmentVariables($env:windir))\TEMP\RuleSet.csv"""

                foreach ( $item in $RuleSet ){
                    Add-ToLog -Message "Setting [$($Item.Path)] property [$($Item.Property)] to [$($Item.DesiredValue)]." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                    $item.CurrentValue = (Get-Item $Item.Path).GetValue($Item.Property)
                    if ( $item.CurrentValue -ne $Item.DesiredValue ){
                        Set-ItemProperty -Path $Item.Path -name $Item.Property -Value $Item.DesiredValue
                        Add-ToLog -Message "Successfully set." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                    }
                    Else {
                        Add-ToLog -Message "Values are equal." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                    }
                    # $ItemPath         = $Item.Path #"""`"""$($Item.Path)`""""
                    # $ItemProperty     = $Item.Property
                    # $ItemDesiredValue = $Item.DesiredValue
                    # Set-ItemProperty -Path $ItemPath -name $ItemProperty -Value $ItemDesiredValue
                }
            }

            try {
                $RuleSet | Select-Object  id, HostName, Property, CurrentValue, DesiredValue | sort-object Id
                $RuleSet | Export-Csv -path "$([Environment]::ExpandEnvironmentVariables($env:windir))\TEMP\RuleSet.csv"

                sudo "Invoke-Command -ScriptBlock ([scriptblock]::Create('$SB'))"

                remove-item -path "$([Environment]::ExpandEnvironmentVariables($env:windir))\TEMP\RuleSet.csv" -Force

            }
            Catch {
                Add-ToLog -Message "Unable to set  property, with error [$_]!" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
            }
        }
    }
    Else {
        $ScriptBlock = {

            $BackupRegistry = $Using:BackupRegistry
            $RuleSet        = $Using:RuleSet

            $PSO = [PSCustomObject]@{
                BackupFileContent = ""
                BackupFileName    = ""
                gsLogBuffer       = ""
                Result            = $false
                Object            = @()
            }

            $FilePath = "$($env:TEMP)\backup-$($env:COMPUTERNAME)-$(Get-date -format 'dd.MM.yy HH-mm-ss').reg"

            if ( $BackupRegistry ){
                Add-ToLog -Message "Backing up, current registry settings." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                foreach ( $Item in $RuleSet ){
                    Export-RegistryToFile -FilePath $FilePath -Path $Item.Path -Property $Item.Property
                }
                $PSO.BackupFileContent = get-content -path $FilePath
                $PSO.BackupFileName    = "backup-$($env:COMPUTERNAME)-$(Get-date -format 'dd.MM.yy HH-mm-ss').reg"
            }

            if ( Test-ElevatedRights ) {
                Try{
                    foreach ( $item in $RuleSet ){
                        Add-ToLog -Message "Setting [$($Item.Path)] property [$($Item.Property)] to [$($Item.DesiredValue)]." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                        $item.CurrentValue = (Get-Item -path $Item.Path).GetValue($Item.Property)
                        if ( $item.CurrentValue -ne $Item.DesiredValue ){
                            Set-ItemProperty -Path $Item.Path -name $Item.Property -Value $Item.DesiredValue
                            Add-ToLog -Message "Successfully set." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                        }
                        Else {
                            Add-ToLog -Message "Values are equal." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                        }
                    }
                    $PSO.Object = $RuleSet
                    $PSO.Result = $true
                }
                Catch {
                    Add-ToLog -Message "Unable to set [$($Item.Path)] property [$($Item.Property)] to [$($Item.DesiredValue)] with error [$_]!" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
                }
            }
            Else {
                Add-ToLog -Message "Unable to set [$($Item.Path)] property [$($Item.Property)] to [$($Item.DesiredValue)] with error [Need elevated rights]!" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
            }

            $PSO.gsLogBuffer = $Global:gsLogBuffer
            return $PSO
        }

        $RemoteUser     = Get-VarFromAESFile -AESKeyFilePath $Global:gsGlobalKey1 -VarFilePath $Global:UserValuePath
        $RemotePass     = Get-VarFromAESFile -AESKeyFilePath $Global:gsGlobalKey1 -VarFilePath $Global:PasswordValuePath
        $Credentials    = New-Object System.Management.Automation.PSCredential -ArgumentList (Get-VarToString -var $RemoteUser), $RemotePass

        Set-Variable -Name "ExportedParameters" -Value $PSBoundParameters -Scope "Global"  -Visibility Public
        $ExportedParameters.Add( "BackupRegistry", $Global:BackupRegistry )
        $ExportedParameters.Add( "RuleSet"       , $RuleSet)

        $Res = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Computer -Credentials $Credentials -ExportedParameters $ExportedParameters -ImportLocalModule "AlexkUtils"

        If ( $Global:BackupRegistry ){
            $FilePath = "$ProjectRoot\$($Global:gsDATAFolder)\$($Res.BackupFileName)"
            $Res.BackupFileContent | set-content -path $FilePath
        }
        foreach ( $Item in $Res.gsLogBuffer ){
            Add-ToLog @Item
        }
    }
}

################################# Script end here ###################################
. "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"