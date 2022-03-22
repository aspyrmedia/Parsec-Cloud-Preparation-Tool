Function Test-RegistryValue {
  param(
    [Alias("PSPath")]
    [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String]$Path
    ,
    [Parameter(Position = 1, Mandatory = $true)]
    [String]$Value
    ,
    [Switch]$PassThru
  ) 

  process {
    if (Test-Path $Path) {
      $Key = Get-Item -LiteralPath $Path
      if ($Key.GetValue($Value, $null) -ne $null) {
        if ($PassThru) {
          Get-ItemProperty $Path $Value
        }
        else {
          $true
        }
      }
      else {
        $false
      }
    }
    else {
      $false
    }
  }
}

$ProgressPreference = 'SilentlyContinue'
$path = [Environment]::GetFolderPath("Desktop")
if ((Test-Path -Path $path\ParsecTemp ) -eq $true) {
} 
Else {
  New-Item -Path $path\ParsecTemp -ItemType directory | Out-Null
}
$ParsecDesktopTemp = "$path\ParsecTemp"
## $currentusersid = Get-LocalUser "$env:USERNAME" | Select-Object SID | ft -HideTableHeaders | Out-String | ForEach-Object { $_.Trim() }

#Unblock-File -Path .\*
#copy-Item .\* -Destination $path\ParsecTemp\ -Force -Recurse | Out-Null
#Start-Sleep -s 1
#Get-ChildItem -Path $path\ParsecTemp -Recurse | Unblock-File

Write-Host "Creating Desktop Temp Folder"
# Create ProgramData\ParsecLoader folder
if ((Test-Path -Path $env:ProgramData\ParsecLoader) -eq $true) {} Else { New-Item -Path $env:ProgramData\ParsecLoader -ItemType directory | Out-Null }
# Create ParsecTemp subfolders folder in C Drive
if ((Test-Path -Path $ParsecDesktopTemp\Apps) -eq $true) {} Else { New-Item -Path $ParsecDesktopTemp\Apps -ItemType directory | Out-Null }
if ((Test-Path -Path $ParsecDesktopTemp\Drivers) -eq $true) {} Else { New-Item -Path $ParsecDesktopTemp\Drivers -ItemType Directory | Out-Null }

Write-Host "Downloading TeamMachineSetup.ps1 and placing it in ProgramData\ParsecLoader"
# Downlaod and locate TeamMachineSetup.ps1 into ProgramData\ParsecLoader folder. This file will poll system for UserData for team ID and associate during Windows Boot.
Invoke-WebRequest -Uri "https://github.com/aspyrmedia/Parsec-Cloud-Preparation-Tool/raw/master/PreInstall/TeamMachineSetup.ps1" -OutFile "$ParsecDesktopTemp\TeamMachineSetup.ps1"
if ((Test-Path $env:ProgramData\ParsecLoader\TeamMachineSetup.ps1) -eq $true) {} Else { Move-Item -Path $ParsecDesktopTemp\TeamMachineSetup.ps1 -Destination $env:ProgramData\ParsecLoader }

Write-Host "Downloading Parsec Binaries"
# Primary, latest Parsec Client
Invoke-WebRequest -Uri "https://builds.parsecgaming.com/package/parsec-windows.exe" -OutFile "$ParsecDesktopTemp\Apps\parsec-windows.exe"
# Parsec Virtual Display Driver
Invoke-WebRequest -Uri "https://builds.parsec.app/vdd/parsec-vdd-0.37.0.0.exe" -OutFile "$ParsecDesktopTemp\Apps\parsec-vdd.exe"
# NEEDED? GPUUpdaterTool
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/parsec-cloud/Cloud-GPU-Updater/master/GPUUpdaterTool.ps1" -OutFile "$env:ProgramData\ParsecLoader\GPUUpdaterTool.ps1"
Get-ChildItem -Path $env:ProgramData\ParsecLoader -Recurse | Unblock-File
Get-ChildItem -Path $ParsecDesktopTemp -Recurse | Unblock-File

## Write-Host "Installing Windows Direct-Play and .Net Framework Core Windows Features"
# Install Windows Features
## Install-WindowsFeature Direct-Play | Out-Null
## Install-WindowsFeature Net-Framework-Core | Out-Null

Write-Host "Installing Parsec Agent"
# Install Parsec Agent
Start-Process -FilePath "$ParsecDesktopTemp\Apps\parsec-windows.exe" -ArgumentList "/silent", "/shared" -NoNewWindow -Wait
Start-Sleep -s 1
# Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
# Start-Sleep -s 1

Write-Host "Disabling Default Display Drivers"
#Disable Devices
Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"' -NoNewWindow -Wait
Get-PnpDevice | where { $_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false
Get-PnpDevice | where { $_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false
Get-PnpDevice | where { $_.friendlyname -like "Google Graphics Array (GGA)" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false
Get-PnpDevice | where { $_.friendlyname -like "Microsoft Hyper-V Video" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false
Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1013&DEV_00B8*"' -NoNewWindow -Wait
Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1D0F&DEV_1111*"' -NoNewWindow -Wait
Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1AE0&DEV_A002*"' -NoNewWindow -Wait

Write-Host "Downloading, copying, and installing Parsec Public Certificate"
# Copy Parsec Public certificate into the folder
Invoke-WebRequest -Uri "https://github.com/aspyrmedia/Parsec-Cloud-Preparation-Tool/raw/master/PreInstall/parsecpublic.cer" -OutFile "$ParsecDesktopTemp\ParsecPublic.cer"
if ((Test-Path $env:ProgramData\ParsecLoader\parsecpublic.cer) -eq $true) {} Else { Copy-Item -Path $ParsecDesktopTemp\ParsecPublic.cer -Destination $env:ProgramData\ParsecLoader }
Import-Certificate -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -FilePath "$env:ProgramData\ParsecLoader\parsecpublic.cer" | Out-Null

Write-Host "Installing Parsec Virtual Display Driver"
# Install Parsec Virtual Display driver
Start-Process "$ParsecDesktopTemp\Apps\parsec-vdd.exe" -ArgumentList "/S" -NoNewWindow -Wait
$iterator = 0    
do {
  Start-Sleep -s 2
  $iterator++
}
Until (($null -ne ((Get-PnpDevice | Where-Object { $_.Name -eq "Parsec Virtual Display Adapter" }).DeviceID)) -or ($iterator -gt 7))
if (Get-process -name parsec-vdd -ErrorAction SilentlyContinue) {
  Stop-Process -name parsec-vdd -Force
}
$configfile = Get-Content $env:ProgramData\Parsec\config.txt
$configfile += "host_virtual_monitors = 1"
$configfile += "host_privacy_mode = 1"
$configfile | Out-File $env:ProgramData\Parsec\config.txt -Encoding ascii

Write-Host "Installing Windows Server 2019 XBox 360 Controller Driver"
# Install XBox 360 Controller driver in Windows Server 2019
if ((gwmi win32_operatingsystem | % caption) -like '*Windows Server 2019*') {
  Invoke-WebRequest -Uri "http://www.download.windowsupdate.com/msdownload/update/v3-19990518/cabpool/2060_8edb3031ef495d4e4247e51dcb11bef24d2c4da7.cab" -OutFile "$ParsecDesktopTemp\Drivers\Xbox360_64Eng.cab"
  if ((Test-Path -Path $ParsecDesktopTemp\Drivers\Xbox360_64Eng) -eq $true) {} Else { New-Item -Path $ParsecDesktopTemp\Drivers\Xbox360_64Eng -ItemType directory | Out-Null }
  # cmd.exe /c "C:\Windows\System32\expand.exe $ParsecDesktopTemp\Drivers\Xbox360_64Eng.cab -F:* $ParsecDesktopTemp\Drivers\Xbox360_64Eng" | Out-Null
  # cmd.exe /c "`"C:\Program Files\Parsec\vigem\10\x64\devcon.exe`" dp_add `"$ParsecDesktopTemp\Drivers\Xbox360_64Eng\xusb21.inf`"" | Out-Null
  Start-Process -FilePath "C:\Windows\System32\expand.exe" -ArgumentList "$ParsecDesktopTemp\Drivers\Xbox360_64Eng.cab", "-F:*", "$ParsecDesktopTemp\Drivers\Xbox360_64Eng" -NoNewWindow -Wait
  Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList "dp_add", "$ParsecDesktopTemp\Drivers\Xbox360_64Eng\xusb21.inf" -NoNewWindow -Wait
}
Write-Host "Final customization scripts"
### Customization for Remote use
# Disable IE Security
Set-Itemproperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -name IsInstalled -value 0 -force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name IsInstalled -Value 0 -Force | Out-Null
## Stop-Process -Name Explorer -Force

# Sets all applications to force close on shutdown
if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) {
  Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
}
Else {
  New-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
}

# Disable new network Public/Private window, default Public
if ((Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff) -eq $true) {} Else { new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null }

# Disable logout start menu
if ((Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff ) -eq $true) { Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null } Else { New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null }

# Disable lock start menu
if ((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else { New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null }
if ((Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) { Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else { New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null }

# Show hidden items
set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1 | Out-Null

# Show file extensions
Set-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name HideFileExt -Value 0 | Out-Null

# Enable Pointer Precision 
Set-Itemproperty -Path 'HKCU:\Control Panel\Mouse' -Name MouseSpeed -Value 1 | Out-Null

# Enable Mouse Keys
set-Itemproperty -Path 'HKCU:\Control Panel\Accessibility\MouseKeys' -Name Flags -Value 63 | Out-Null

# Set automatic time and timezone
Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null

# Disables Server Manager opening on Startup
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null

# Installing VB Cable Audio Driver if required
# $gputype = Get-PnpDevice | Where-Object { ($_.DeviceID -like 'PCI\VEN_10DE*' -or $_.DeviceID -like '*PCI\VEN_1002*') -and ($_.PNPClass -eq 'Display' -or $_.Name -like '*Video Controller') } | Select-Object InstanceID -ExpandProperty InstanceID
# if ($gputype -eq $null) {
# }
# Else {
#   if ($gputype.substring(13, 8) -eq "DEV_13F2") {
#     #AWS G3.4xLarge M60
#     AudioInstall
#   }
#   ElseIF ($gputype.Substring(13, 8) -eq "DEV_118A") {
#     #AWS G2.2xLarge K520
#     AudioInstall
#   }
#   Elseif ($gputype.substring(13, 8) -eq "DEV_15F8") {
#     #Tesla P100
#     AudioInstall
#   }
#   Elseif ($gputype.substring(13, 8) -eq "DEV_1BB3") {
#     #Tesla P4
#     AudioInstall
#   }
#   Elseif ($gputype.substring(13, 8) -eq "DEV_1EB8") {
#     #Tesla T4
#     AudioInstall
#   }
#   Elseif ($gputype.substring(13, 8) -eq "DEV_1430") {
#     #Quadro M2000
#     AudioInstall
#   }
#   Elseif ($gputype.substring(13, 8) -eq "DEV_7362") {
#     #AMD V520
#     AudioInstall
#   }
#   Else {
#   }
# }

#Audio Driver Install
<#
    (New-Object System.Net.WebClient).DownloadFile("http://rzr.to/surround-pc-download", "C:\ParsecTemp\Apps\razer-surround-driver.exe")
    ExtractRazerAudio
    ModidifyManifest
    $OriginalLocation = Get-Location
    Set-Location -Path 'C:\ParsecTemp\Apps\razer-surround-driver\$TEMP\RazerSurroundInstaller\'
    Start-Process RzUpdateManager.exe
    Set-Location $OriginalLocation
    Set-Service -Name audiosrv -StartupType Automatic
    #>
# (New-Object System.Net.WebClient).DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "C:\ParsecTemp\Apps\VBCable.zip")
# New-Item -Path "C:\ParsecTemp\Apps\VBCable" -ItemType Directory | Out-Null
# Expand-Archive -Path "C:\ParsecTemp\Apps\VBCable.zip" -DestinationPath "C:\ParsecTemp\Apps\VBCable"
# $pathToCatFile = "C:\ParsecTemp\Apps\VBCable\vbaudio_cable64_win7.cat"
# $FullCertificateExportPath = "C:\ParsecTemp\Apps\VBCable\VBCert.cer"
# $VB = @{}
# $VB.DriverFile = $pathToCatFile;
# $VB.CertName = $FullCertificateExportPath;
# $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
# $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
# [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
# Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
# Start-Process -FilePath "C:\ParsecTemp\Apps\VBCable\VBCABLE_Setup_x64.exe" -ArgumentList '-i', '-h'
# Set-Service -Name audiosrv -

# StartupType Automatic
# Start-Service -Name audiosrv

Write-Host "Cleaning up Temp folder"
# Cleanup
Remove-Item -Path $ParsecDesktopTemp -force -Recurse | Out-Null
Remove-item "$env:AppData\Microsoft\Windows\Recent\*" -Recurse -Force | Out-Null

Write-Host "Configuring on boot task to look at User Data for Parsec Team Data"
# Attempts to read instance userdata and set up as Team Machine at startup
$XML = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Attempts to read instance userdata and set up as Team Machine at startup</Description>
    <URI>\Setup Team Machine</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$(([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value)</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-file %programdata%\ParsecLoader\TeamMachineSetup.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
"@

try {
  Get-ScheduledTask -TaskName "Setup Team Machine" -ErrorAction Stop | Out-Null
  Unregister-ScheduledTask -TaskName "Setup Team Machine" -Confirm:$false
}
catch {}
$action = New-ScheduledTaskAction -Execute 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-file %programdata%\ParsecLoader\TeamMachineSetup.ps1'
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -XML $XML -TaskName "Setup Team Machine" | Out-Null
