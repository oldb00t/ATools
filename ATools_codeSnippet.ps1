Set-ExecutionPolicy Unrestricted;
iex ((New-Object System.Net.WebClient).DownloadString('http://boxstarter.org/bootstrapper.ps1'));
get-boxstarter -Force;
Install-BoxstarterPackage -PackageName 'https://raw.githubusercontent.com/oldb00t/ATools/master/Core_Tools.ps1';
