# POWERSHELL to create certs on AWS Win2016 hosts to allow Ansible to authenticate over WinRM
# Since AWS VMs pick up a new hostname each reboot, a new Device Certificate is required at reboot.
# The Device Certificate cannot be self-signed, so a fake caCert is used to sign it.

write-host "Running Boot-time script to create Device Cert"

Set-StrictMode -Version Latest
# Ensure we stop if commandlet throws error
$ErrorActionPreference = "Stop"


function msys2-Call {
    param (
        [string]$ScriptBlock,
        [string]$Message,
        [string]$ErrorAction = $ErrorActionPreference
    )
    if ( $Message ) {
      # Prevent password being shown in the clear
      Write-Host "$Message"
    }
    else {
      Write-Host "$ScriptBlock"
    }
    # The 'Out-Null' makes powershell wait for minntty process to complete before continuing.
    # ScriptBlock can be powershell multi-line string e.g. @" multi-line text "@
    # ScriptBlock must escape quotes e.g. \"
    # DEBUG by replacing '-w hide' with '-h always'. This leaves the msys2 console open until you manually close it. 
    & C:\tools\msys64\usr\bin\mintty.exe -w hide /bin/env MSYSTEM=MSYS64 /bin/bash -l -c "$ScriptBlock" | Out-Null
    $commandErrorCode = $LastExitCode
    if (($commandErrorCode -ne 0) -and $ErrorAction -eq "Stop") {
      Write-Warning "Command failed with RC=$commandErrorCode"
      Write-Warning "  $ScriptBlock"
      exit $commandErrorCode
    }
}

$programDataDir = 'C:\ProgramData\devops'
$msysProgramDataDir = '/c/ProgramData/devops'

$passwordFile = "$programDataDir\.DEVOPS_ROOTCA_PASSWORD"

# Check for mandatory environment variables
if ( test-path $passwordFile ) {
  # Load password from private user file.
  $securePassword = Get-Content $passwordFile | convertTo-SecureString
  $DEVOPS_ROOTCA_PASSWORD = (New-Object PSCredential "user",$securePassword).GetNetworkCredential().Password
}
else {
  Write-Warning "Cannot load SecureString from: $passwordFile"
  Write-Error "Check the README.md file for help on running this script"
}


# Get the public hostname from the AWS instance metadata service
# $certHostname = (curl http://169.254.169.254/latest/meta-data/public-hostname).content
$certHostname = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname

$caKeyPath = "${programDataDir}\rootca.key"
$caCertPath = "$programDataDir\rootca.crt"
$deviceKeyPath = "$programDataDir\device.key"
$deviceCertPath = "$programDataDir\device.crt"
$opensslConfigPath = "${programDataDir}\openssl-ext.conf"

$currentThumbprintFile = "$programDataDir\device.current.thumprint"

# Check for a device key

if ( !(test-path $deviceKeyPath)) {
  Write-Warning "'Administrator' hasnt been configured to run this script"
  Write-Warning"  Cannot find the key path: $deviceKeyPath"
  exit 0
}

# User creates a csr(certificate signing request) from the key
msys2-Call `
    -Message "Create a CSR for device: ${certHostname}" `
    -ScriptBlock @"
set -e

expect <<HEREDOC
spawn openssl \
  req                       \
  -new                      \
  -key ${msysProgramDataDir}/device.key           \
  -out ${msysProgramDataDir}/device.csr          
expect \"Country Name\"
send \"GB\r\"
expect \"State or Province Name\"
send \".\r\"
expect \"Locality Name\"
send \".\r\"
expect \"Organization Name\"
send \"Canon\r\"
expect \"Organizational Unit Name\"
send \"tmvse\r\"
expect \"Common Name\"
send \"${certHostname}\r\"
expect \"Email Address\"
send \"devops@local.tmvse.com\r\"
expect \"A challenge password\"
send \"${DEVOPS_ROOTCA_PASSWORD}\r\"
expect \"An optional company name\"
send \"Canon\r\"
expect eof
HEREDOC
"@

msys2-call `
    -Message "Create a device cert for device: ${certHostname}" `
    -ScriptBlock @"
set -e

expect <<HEREDOC
spawn openssl \
    x509                                      \
    -req                                      \
    -CA ${msysProgramDataDir}/rootca.crt      \
    -CAkey ${msysProgramDataDir}/rootca.key   \
    -CAcreateserial                           \
    -extensions client_server_ssl             \
    -extfile ${msysProgramDataDir}/openssl-ext.conf \
    -sha256                                   \
    -days 365                                 \
    -in ${msysProgramDataDir}/device.csr      \
    -out ${msysProgramDataDir}/device.crt
expect \"Enter pass phrase\"
send \"${DEVOPS_ROOTCA_PASSWORD}\r\"
expect eof
HEREDOC
"@

$deviceCertThumbprint = (Import-Certificate -FilePath $deviceCertPath -CertStoreLocation Cert:\LocalMachine\My).Thumbprint

if ( test-path ${currentThumbprintFile} ) {
  # Delete current cert
  $currentThumbprint = get-content ${currentThumbprintFile}
  $certPath = "Cert:\LocalMachine\My\${currentThumbprint}"
  
  try {
    write-host "Removing current cert = $certPath"
    Remove-Item -Path ${certPath}
  }
  catch {
    write-host "Cannot remove current cert = $certPath"
  }
  
  try {
    write-host "Removing current cert file = $currentThumbprintFile"
    Remove-Item -Path ${currentThumbprintFile}
  }
  catch {
    write-host "Cannot clean up current thumbprint file"
  }
}

# keep a copy of the thumbprint for rext run
write-host "NEW THUMBPRINT: $deviceCertThumbprint"
echo $deviceCertThumbprint > ${currentThumbprintFile}

# Only recreate the WinRM HTTPS listener if it already exists
$listeners = Get-ChildItem WSMan:\localhost\Listener
If ($listeners | Where {$_.Keys -like "TRANSPORT=HTTPS"}) {
  # Recreate the WinRM Listener with this new Cert
  $valueset = @{
      CertificateThumbprint = $deviceCertThumbprint
      Hostname = $certHostname
  }

  # Delete the listener for SSL
  $selectorset = @{
      Address = "*"
      Transport = "HTTPS"
  }
  Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset

  # Add new Listener with new SSL cert
  New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
}



