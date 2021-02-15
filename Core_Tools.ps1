##### set power options
& powercfg -change -monitor-timeout-ac 0 | Out-Null
& powercfg -change -monitor-timeout-dc 0 | Out-Null
& powercfg -change -disk-timeout-ac 0 | Out-Null
& powercfg -change -disk-timeout-dc 0 | Out-Null
& powercfg -change -standby-timeout-ac 0 | Out-Null
& powercfg -change -standby-timeout-dc 0 | Out-Null
& powercfg -change -hibernate-timeout-ac 0 | Out-Null
& powercfg -change -hibernate-timeout-dc 0 | Out-Null

# remove windows junk 

# Get-AppxPackage -AllUsers | Select Name, PackageFullName | Sort Name

Get-AppxPackage *3dbuilder* | Remove-AppxPackage
Get-AppxPackage *windowsalarms* | Remove-AppxPackage
Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage *windowscamera* | Remove-AppxPackage
Get-AppxPackage *officehub* | Remove-AppxPackage
Get-AppxPackage *skypeapp* | Remove-AppxPackage
Get-AppxPackage *getstarted* | Remove-AppxPackage
Get-AppxPackage *zunemusic* | Remove-AppxPackage 
Write-Output "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTravel" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.FreshPaint" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.HelpAndTips" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Media.PlayReadyClient.2" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MoCamera" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
Get-AppxPackage "Microsoft.OfficeLens" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Reader" | Remove-AppxPackage
Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Todos" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WebMediaExtensions" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Whiteboard" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsReadingList" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsScan" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WinJS.1.0" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WinJS.2.0" | Remove-AppxPackage
Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Advertising.Xaml" | Remove-AppxPackage
Get-AppxPackage *3dbuilder* | Remove-AppxPackage
Get-AppxPackage *windowsalarms* | Remove-AppxPackage
Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage *windowscamera* | Remove-AppxPackage
Get-AppxPackage *officehub* | Remove-AppxPackage
Get-AppxPackage *skypeapp* | Remove-AppxPackage
Get-AppxPackage *getstarted* | Remove-AppxPackage
Get-AppxPackage *zunemusic* | Remove-AppxPackage
Get-AppxPackage *windowsmaps* | Remove-AppxPackage
Get-AppxPackage *solitairecollection* | Remove-AppxPackage
Get-AppxPackage *bingfinance* | Remove-AppxPackage
Get-AppxPackage *zunevideo* | Remove-AppxPackage
Get-AppxPackage *bingnews* | Remove-AppxPackage
Get-AppxPackage *onenote* | Remove-AppxPackage
Get-AppxPackage *people* | Remove-AppxPackage
Get-AppxPackage *windowsphone* | Remove-AppxPackage
Get-AppxPackage *photos* | Remove-AppxPackage
Get-AppxPackage *windowsstore* | Remove-AppxPackage
Get-AppxPackage *bingsports* | Remove-AppxPackage
Get-AppxPackage *soundrecorder* | Remove-AppxPackage
Get-AppxPackage *bingweather* | Remove-AppxPackage
Get-AppxPackage *xboxapp* | Remove-AppxPackage
Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppPackage

Write-Output "Uninstalling default third party applications..."
Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
Get-AppxPackage "A278AB0D.DragonManiaLegends" | Remove-AppxPackage
Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
Get-AppxPackage "AD2F1837.GettingStartedwithWindows8" | Remove-AppxPackage
Get-AppxPackage "AD2F1837.HPJumpStart" | Remove-AppxPackage
Get-AppxPackage "AD2F1837.HPRegistration" | Remove-AppxPackage
Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
Get-AppxPackage "Amazon.com.Amazon" | Remove-AppxPackage
Get-AppxPackage "C27EB4BA.DropboxOEM" | Remove-AppxPackage
Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
Get-AppxPackage "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC" | Remove-AppxPackage
Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
Get-AppxPackage "Fitbit.FitbitCoach" | Remove-AppxPackage
Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "king.com.FarmHeroesSaga" | Remove-AppxPackage
Get-AppxPackage "Nordcurrent.CookingFever" | Remove-AppxPackage
Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
Get-AppxPackage "PricelinePartnerNetwork.Booking.comBigsavingsonhot" | Remove-AppxPackage
Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
Get-AppxPackage "ThumbmunkeysLtd.PhototasticCollage" | Remove-AppxPackage
Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage


############
# back desktop
set-itemproperty -path 'HKCU:\Control Panel\Colors' -name Background -value "0 0 0"

#Remove Teams Machine-Wide Installer

Write-Host "Removing Teams Machine-wide Installer" -ForegroundColor Yellow
$MachineWide = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Teams Machine-Wide Installer"}
$MachineWide.Uninstall()


Write-Output "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage

Write-Output "Lowering UAC level..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0A


Write-Output "Setting Control Panel view to small icons..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1


Write-Output "Setting Dark Mode for System..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0

Write-Output "Showing hidden files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1



###############################################################################
# System Configuration
###############################################################################
# Set up Chocolatey
Write-Host "Initializing chocolatey"


$fireeyeFeed      = "https:/www.myget.org/F/fireeye/api/v2"
$flareFeed        = "https://www.myget.org/F/fireeye/api/v2"

# REPOS

choco sources add -n=fireeye -s $fireeyeFeed --priority 1
choco sources add -n=flare -s $flarefeed --priority 1

# JUST INSTALL NO CHECKS
choco feature enable -n allowGlobalConfirmation
choco feature enable -n allowEmptyChecksums

$Boxstarter.RebootOk=$true # Allow reboots?
$Boxstarter.NoPassword=$false # Is this a machine with no login password?
$Boxstarter.AutoLogin=$true # Save my password securely and auto-login after a reboot
if (Test-Path "C:\BGinfo\build.cfg" -PathType Leaf)
{
    REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
}
# Basic setup
Write-Host "Setting execution policy"
Update-ExecutionPolicy Unrestricted
Set-WindowsExplorerOptions -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowHiddenFilesFoldersDrives
Disable-BingSearch
Disable-GameBarTips
Disable-ComputerRestore -Drive ${Env:SystemDrive}
# Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d "0" /f 
if (Test-Path "C:\BGinfo\build.cfg" -PathType Leaf)
{
write-host "Disabling Windows garbage from free VM!"
cmd.exe /c sc config sshd start= disabled
cmd.exe /c sc stop sshd
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "bginfo" /f 
}
# Disable Updates
write-host "Disabling Windows Update"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d "1" /f 

# Disable Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Kill Windows Defender
write-host "Disabling Windows Defender"
Stop-Service WinDefend
Set-Service WinDefend -StartupType Disabled
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Disable Action Center
write-host "Disabling Action Center notifications"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d "0x1" /f 

# Set windows Aero theme
write-host "Use Aero theme"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v DllName /t REG_EXPAND_SZ /d "%SystemRoot%\resources\themes\Aero\Aero.msstyles" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v ThemeActive /t REG_SZ /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v CurrentTheme /t REG_SZ /d "C:\Windows\resources\Themes\aero.theme" /f

# Set a nice S1 wallpaper : 
write-host "Setting a nice wallpaper"
$web_dl = new-object System.Net.WebClient
$wallpaper_url = "https://raw.githubusercontent.com/SentineLabs/SentinelLabs_RevCore_Tools/master/Logo_Wallpaper_Desktop_1920x1080.png"
$wallpaper_file = "C:\Users\Public\Pictures\101089633-48da3e80-356a-11eb-9d66-0cdf9da30220.png"
$web_dl.DownloadFile($wallpaper_url, $wallpaper_file)
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\Users\Public\Pictures\101089633-48da3e80-356a-11eb-9d66-0cdf9da30220.png" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v WallpaperStyle /t REG_DWORD /d "0" /f 
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v StretchWallpaper /t REG_DWORD /d "2" /f 
reg add "HKEY_CURRENT_USER\Control Panel\Colors" /v Background /t REG_SZ /d "0 0 0" /f

###############################################################################
# Utilities, Debugger, Disassembler, Scripting
###############################################################################
choco install sigma.fireeye
choco install hashcheck
choco install cyberchef.flare
choco install nmap.fireeye
choco install autoit.fireeye

choco install putty
choco install vnc-viewer.fireeye
choco install fakenet-ng.python.fireeye
choco install 7zip.install
choco install procmon
choco install battoexeconverter
choco install office365proplus
choco install hxd
choco install sysinternals
choco install processhacker
choco install burp-suite-free-edition
choco install networkmonitor
choco install ghidra
choco install brave
choco install pestudio
choco install sandboxie
choco install fakenet
choco install procmon
choco install vt-cli
choco install kss
choco install pebear
choco install ppee
choco install floss
choco install virustotaluploader
choco install yara
choco install codelite
choco install mingw
choco install python
choco install pycharm-edu
choco install vclip
choco install screentogif
choco install fakenet
choco install wireshark
choco install networkmonitor
choco install sandboxie
choco install regshot
choco install psscriptanalyzer
choco install vim
choco install notepadplusplus
choco install zap
choco install winscp.install
choco install greenshot
choco install explorersuite
choco install hashcheck
choco install autoruns
choco install vscode
choco install xmind
choco install foca
choco install docker-desktop
choco install sigma.fireeye
choco install hashcheck
choco install cyberchef.flare
choco install nmap.fireeye
choco install autoit.fireeye

choco install openjdk11 -y
setx -m JAVA_HOME "C:\Program Files\Java\jdk-11.0.2\"
cinst ghidra
choco install python -y
refreshenv
choco install pip -y
python -m pip install --upgrade pip
pip install --upgrade setuptools
pip install pefile
pip install yara
choco install notepadplusplus -y

###############################################################################
# Create Desktop Shortcut
###############################################################################
if (Test-Path "C:\BGinfo\build.cfg" -PathType Leaf)
{
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\Ghidra.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_9.1.2_PUBLIC\ghidraRun.bat"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\x64dbg.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\x64dbg.portable\tools\release\x64\x64dbg.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\x32dbg.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\x64dbg.portable\tools\release\x32\x32dbg.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\OLLYDBG.lnk" -TargetPath "C:\Program Files (x86)\OllyDbg\OLLYDBG.EXE"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\HxD.lnk" -TargetPath "C:\Program Files\HxD\HxD.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\PEbear.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\pebear\tools\PE-bear.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\pestudio.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\PeStudio\tools\pestudio\pestudio.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\proexp.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\procexp\tools\procexp.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\Autoruns.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\AutoRuns\tools\Autoruns.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\Sysmon.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\sysmon\tools\Sysmon.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\Tcpview.lnk" -TargetPath "C:\ProgramData\chocolatey\lib\TcpView\Tools\Tcpview.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\notepad++.lnk" -TargetPath "C:\Program Files\Notepad++\notepad++.exe"
Install-ChocolateyShortcut -ShortcutFilePath "C:\Users\IEUser\Desktop\Cmder.lnk" -TargetPath "C:\tools\Cmder\Cmder.exe"
}
Write-Host -NoNewline " - SentinelLabs RevCore Tools HAS COMPLETED! - "
