# Rename this file to Settings-[..].ps1
######################### value replacement #####################

[string] $Global:Computers = ""         
[string]$Global:UserValuePath                 = ""         
[string]$Global:PasswordValuePath             = ""         


######################### no replacement ########################
[bool] $Global:BackupRegistry = $true


[bool]  $Global:LocalSettingsSuccessfullyLoaded  = $true
# Error trap
trap {
    $Global:LocalSettingsSuccessfullyLoaded = $False
    exit 1
}
