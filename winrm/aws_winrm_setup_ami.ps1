# POWERSHELL to set up certs on AWS Win2016 hosts to allow Ansible to authenticate over WinRM
# REFERENCE: https://docs.ansible.com/ansible/latest/user_guide/windows_winrm.html
#
# AWS hosts reboot with new IP and hostname (assuming it's not using elasticIP).
# The WinRM HTTPS listener requires:
#    1. a Device cert i.e. it's CN contains the (public?) hostname
#    2. a Device Cert that is no self-signed
# On reboot, the listener will need to be started with the new certificate.

$env:chocolateyVersion = '0.10.13'
$env:msysVersion = '20180531.0.0'
$env:zipVersion = '19.0'

Set-StrictMode -Version Latest
# Ensure we stop if commandlet throws error
$ErrorActionPreference = "Stop"

# Ensure we stop if exe returns non-zero RC
function Invoke-Call {
    param (
        [scriptblock]$ScriptBlock,
        [string]$ErrorAction = $ErrorActionPreference
    )
    & @ScriptBlock
    if (($lastexitcode -ne 0) -and $ErrorAction -eq "Stop") {
      Write-Warning "Command failed with RC=$lastexitcode"
      Write-Warning "  $ScriptBlock"
      exit $lastexitcode
    }
}

function msys2-Call {
    param (
        [string]$ScriptBlock,
        [string]$ErrorAction = $ErrorActionPreference
    )
    Write-host "Running command: $ScriptBlock"
    # The 'Out-Null' makes powershell wait for minntty process to complete before continuing.
    C:\tools\msys64\usr\bin\mintty.exe /bin/env MSYSTEM=MSYS64 /bin/bash -l -c "$ScriptBlock" | Out-Null
    $commandErrorCode = $LastExitCode
    if (($commandErrorCode -ne 0) -and $ErrorAction -eq "Stop") {
      Write-Warning "Command failed with RC=$commandErrorCode"
      Write-Warning "  $ScriptBlock"
      exit $commandErrorCode
    }
}

$programDataDir = "C:\ProgramData\devops"
if ( !(test-path $programDataDir)) {
  New-Item -ItemType Directory -Force -Path $programDataDir
}
#####################################################################
# TODO: Secure $programDataDir directory to SYSTEM and Administrators only
#####################################################################

# Create a password file for aws_winrm_bootup.ps1 script to open rootca.crt
$rootCaPasswordFile = "$programDataDir\.DEVOPS_ROOTCA_PASSWORD"
$caCertArchive = '.\files\.cacert.zip'
if ( !(test-path $rootCaPasswordFile)) {
  $securePassword = read-host -Prompt "Enter password for: $caCertArchive" -AsSecureString
  $securePassword | convertFrom-SecureString > $rootCaPasswordFile
}
# $DEVOPS_ROOTCA_PASSWORD = Get-Content $rootCaPasswordFile

# Handle problem with new AWS boxes not resolving DNS lookups
Clear-DnsClientCache

# Install Chocolatey if not present
if ((Get-Command "choco.exe" -ErrorAction SilentlyContinue) -eq $null) { 
  $env:chocolateyUseWindowsCompression = 'true'
  .\chocolatey\install-choco.ps1

  # Reload the path so we can call choco
  set PATH=C ->
}


# If not already installed, install 7zip using choco 
if ((Get-Command "7z.exe" -ErrorAction SilentlyContinue) -eq $null) { 
  Invoke-Call -ScriptBlock { 
    cmd.exe /c "choco.exe install -y 7zip --version '$env:zipVersion'"
  }

  # Reload the path so we can call mintty
  set PATH=C ->
}

# If not already installed, nstall msys2 using choco
if ((Get-Command "msys2.exe" -ErrorAction SilentlyContinue) -eq $null) { 
  Invoke-Call -ScriptBlock { 
    cmd.exe /c "choco.exe install -y msys2 --version '$env:msysVersion'"
  }

  # Reload the path so we can call mintty
  set PATH=C ->
}


# Install openssl in msys2 console
msys2-Call -ScriptBlock @" 
  set -e
  pacman --needed --noconfirm -S msys/openssl
"@

# Install expect in msys2 console
msys2-Call -ScriptBlock @" 
  set -e
  pacman --needed --noconfirm -S msys/expect
"@

if ( !(test-path $programDataDir\rootca.crt)) {
  # Unobfiscate password
  $cetificateZipPassword = (New-Object PSCredential "user",$securePassword).GetNetworkCredential().Password
  Write-Host "Copying rootca key and cert"
  Invoke-Call -ScriptBlock {
    7z.exe e -y -p"$cetificateZipPassword" -o"$programDataDir" $caCertArchive
  }
  
  # Install rootca cert into root 
  Import-Certificate -FilePath $programDataDir\rootca.crt -CertStoreLocation Cert:\LocalMachine\Root
  
}


# TODO: probably need a DEV switch to only copy if DEVELOPING.
$startupScriptName = "aws_winrm_bootup.ps1"
$sourceStartupFile = ".\files\${startupScriptName}"
$startupScriptPath = "${programDataDir}\${startupScriptName}"
copy-item $sourceStartupFile -destination $programDataDir

$opensslConfigName = "openssl-ext.conf"
$opensslConfigFile = ".\files\${opensslConfigName}"
$opensslConfigPath = "${programDataDir}\${opensslConfigName}"
copy-item $opensslConfigFile -destination $programDataDir

# Create the device key (doesn't change and will be used to create the device cert at startup)
# Convert Win path to msys2 path
if ( !(test-path ${programDataDir}\device.key )) {
  msys2-Call -ScriptBlock @"
    set -e
    # Use the msys2 path to Windows user
    openssl genrsa -out /c/ProgramData/devops/device.key 2048 
"@
}

# Configure Group Policy to run script on machine startup
$startupConfigDir = 'C:\Windows\System32\GroupPolicy\Machine\Scripts'
$startupConfigScript = "${startupConfigDir}\psscripts.ini"
# Directory doesnt exist in new VM
if ( ! (test-path $startupConfigDir )) {
  New-Item -Path "$startupConfigDir" -ItemType Directory
}

$startupConfigText = @"

[Startup]
0CmdLine=${startupScriptPath}
0Parameters=
"@

if ( ! (test-path "$startupConfigScript" )) {
  $startupConfigText | Out-File -FilePath "$startupConfigScript" 
}
else {
  if ( ! (Select-String -Path "$startupConfigScript" -Pattern "$startupScriptName" -SimpleMatch -Quiet)) {
    write-host "Found pre-existing startup file: $startupConfigScript"
    write-error "Needs to contain something like: $startupConfigText"
  }
}
# Call script to create device cert
powershell.exe -ExecutionPolicy ByPass -File $startupScriptPath -Verbose


$github_scripts_path = 'github-ansible.ansible'

Write-Host "ENSURING AUTO LOGIN IS DISABLED"
$reg_winlogon_path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $reg_winlogon_path -Name AutoAdminLogon -Value 0
Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultUserName -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $reg_winlogon_path -Name DefaultPassword -ErrorAction SilentlyContinue


Write-Host "CONFIGURE WINRM FOR ANSIBLE TO USE"
#$certHostname = (curl http://169.254.169.254/latest/meta-data/public-hostname).content
$certHostname = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

# The @ ensures we always return an array; single results can return an object and count fails
$hostCertList = @(Get-ChildItem -Path cert:\LocalMachine\My | ?{ $_.Subject -Like "*CN=${certHostname}*"  })
$certCount = ($hostCertList).count
if ( $certCount -gt 1 ) {
  Write-Error "[FIXME] There should only be one device cert where: CN=${certHostname}"
}

if ( $certCount -eq 0 ) {
  Write-Error "Device Cert missing for: CN=$certHostname"
}

# Setup system to allow Ansible over WinRM using certs
# $file_url = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
# WARNING: THIS FILE HAS BEEN MODIFIED TO USE A DEVICE CERT SIGNED BY DEVOPS ROOTCA
$winrm_config_file = "$github_scripts_path\ConfigureRemotingForAnsible.ps1"
powershell.exe                `
  -ExecutionPolicy ByPass     `
  -File $winrm_config_file    `
  -GlobalHttpFirewallAccess 0 `
  -ForceNewSSLCert            `
  -EnableCredSSP              `
  -DisableBasicAuth           `
  -SkipNetworkProfileCheck    `
  -SubjectName $certHostname `
  -Verbose


# Service Control: Start WinRM
sc.exe config "WinRM" start=auto

Write-Host "WinRM has been configured as follows:"
winrm get 'winrm/config'
