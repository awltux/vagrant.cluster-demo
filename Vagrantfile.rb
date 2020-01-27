
require 'shellwords'

nicRoutePath = "/etc/sysconfig/network-scripts/route-eth1"

sshKeyName = "vagrant"
#sshKeyName = "devops.id_rsa"
ssh_prv_key_path = "#{Dir.home}/.ssh/#{sshKeyName}"
ssh_prv_key = ""
# Windows user running Vagrant has to have keys available
if File.file?("#{ssh_prv_key_path}")
  ssh_prv_key = File.read("#{ssh_prv_key_path}")
else
  puts "No SSH key found: #{ssh_prv_key_path}"
  puts "You will need to remedy this before running this Vagrantfile."
  exit 1
end

# Called from this.configureHost
# Each host calls this for each member of the cluster
$network_config_linux = <<-ADD_NETWORK_CONFIG_LINUX_HEREDOC
#!/bin/bash -eu

currentVmIp=$1
targetHostName=$2
targetNatIp=$3
targetNatNetCidr=$4
targetNatNetIp=$5
targetNatNetMask=$6
targetVmIp=$7
ldapRealm=$8

if [[ $# -ne 8 ]]; then
  echo "[ERROR] Invalid number of parameters for network_config_linux: $#"
  exit 1
fi

# Populate /etc/hosts with other servers in vagrant project
if ! grep -q "${targetHostName}" /etc/hosts; then
  echo "# HOST ADDED: ${targetNatIp} ${targetHostName}"
  echo "${targetNatIp} ${targetHostName}.${ldapRealm} ${targetHostName}" >> /etc/hosts
fi

# Create non-persistent route for current boot
if ! ip route | grep -q "${targetNatNetCidr}.*via ${targetVmIp}"; then
  echo "# IP ROUTE ADDED [TEMPORARY]: ${targetNatNetCidr} via ${targetVmIp} dev eth1"
  ip route add ${targetNatNetCidr} via ${targetVmIp} dev eth1
fi

# Create persistent route for future boots
touch #{nicRoutePath}
if ! grep -q "^ADDRESS[0-9]\+=${targetNatNetIp}" #{nicRoutePath}; then
  routeCount=$(grep "^ADDRESS.*" #{nicRoutePath} | wc -l )
  echo "# IP ROUTE ADDED [PERSISTENT]: ADDRESS${routeCount}=${targetNatNetIp} NETMASK${routeCount}=${targetNatNetMask} GATEWAY${routeCount}=${targetVmIp}"
  cat >> #{nicRoutePath} <<INNER_HEREDOC
    ADDRESS${routeCount}=${targetNatNetIp}
    NETMASK${routeCount}=${targetNatNetMask}
    GATEWAY${routeCount}=${targetVmIp}
INNER_HEREDOC
fi

ADD_NETWORK_CONFIG_LINUX_HEREDOC


# Called from this.configureHost
# Each host calls this for each member of the cluster
$network_config_win10 = <<-ADD_NETWORK_CONFIG_WIN10_HEREDOC
# powershell

$currentVmIp=$args[0]
$targetHostName=$args[1]
$targetNatIp=$args[2]
$targetNatNetCidr=$args[3]
$targetNatNetIp_NOT_USED_FOR_WIN10=$args[4]
$targetNatNetMask_NOT_USED_FOR_WIN10=$args[5]
$targetVmIp=$args[6]
$ldapRealm=$args[7]

if (-NOT ($args.count -eq 8)) {
  echo "[ERROR] Invalid paramter count for network_config_win10: $($args.count)"
  exit 1
}

function Add-NetRouteByDestination {
  param (
    [Parameter(Mandatory=$true)][String]$destinationCidr,
    [Parameter(Mandatory=$true)][String]$interfaceIpString,
    [Parameter(Mandatory=$true)][String]$gatewayIpString
  )
  echo "Check route for: destinationCidr=$destinationCidr interfaceIpString=$interfaceIpString gatewayIpString=$gatewayIpString"
  $interfaceIp=get-netipaddress $interfaceIpString
  $interfaceIdx=$interfaceIp.InterfaceIndex
  try {
    New-NetRoute -DestinationPrefix $destinationCidr -InterfaceIndex $interfaceIdx -NextHop $gatewayIpString -ea stop | out-null
    echo "    Route added for $destinationCidr"
  }
  catch [Microsoft.Management.Infrastructure.CimException] {
    echo "    Route already exists for $destinationCidr"
  }
}

function Add-ResolveHost {
  param (
    [Parameter(Mandatory=$true)][String]$ipAddress,
    [Parameter(Mandatory=$true)][String]$hostname
  )
  echo "Check /etc/hosts for: ipAddress=$ipAddress hostname=$hostname"
  $lineToInsert = $ipAddress + '    ' + $hostname + '.' + $ldapRealm + ' ' + $hostname
  $filename = "$env:windir\\System32\\drivers\\etc\\hosts"
  $content = Get-Content $filename
  $foundLine=$false

  foreach ($line in $content) {
    if ($line -match ${ipAddress} + '\s+' + ${hostname}) {
      $foundLine=$true
    }
  }
  if (-not $foundLine) {
    echo "    Inserted"
    $lineToInsert | Out-File -encoding ASCII -append $filename
  } else {
    echo "    Already exists"
  }
  
}

# ROUTING RULES: Add routes to NAT interfaces.
Add-NetRouteByDestination $targetNatNetCidr $currentVmIp $targetVmIp
# FAKE DNS: Allow other hosts to be resolved
Add-ResolveHost $targetNatIp $targetHostName

# IP routing/forwarding: Allows network packets to be routed across interfaces
reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /D 1 /f | out-null
sc.exe config RemoteAccess start= auto | out-null
sc.exe start RemoteAccess | out-null

# FIREWALL: Allow pings from each NAT interface; also see HOST_CONFIG_WIN10_HEREDOC
New-NetFirewallRule -DisplayName "Allow inbound ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress ${targetNatNetCidr} -Action Allow | out-null
New-NetFirewallRule -DisplayName "Allow inbound ICMPv6" -Direction Inbound -Protocol ICMPv6 -IcmpType 8 -RemoteAddress ${targetNatNetCidr} -Action Allow | out-null

ADD_NETWORK_CONFIG_WIN10_HEREDOC


# Called from this.configureHost
# Called once per host
# This runs as root so that it can setup the ansible account and it's sudo config.
# Create the ansible user and add them to sudo.
# Copy vagrant ssh keys to ansibleUser
# Enable password login to support kerberos login
$host_config_linux = <<-HOST_CONFIG_LINUX_HEREDOC
#!/bin/bash -eu
echo "######################################################"
echo "[Vagrantfile.host_config_linux]  $(hostname)"
echo "######################################################"


ansibleAccount=$1
ansiblePassword=$2
vaultPassword=$3
sshPrivateKeyString="#{ssh_prv_key}"

if [[ $# -ne 3 ]]; then
  echo "[ERROR] Invalid number of parameters for host_config_linux: $#"
  exit 1
fi

homeDir="/home/${ansibleAccount}"

if ! id -u ${ansibleAccount} > /dev/null 2>&1; then
  echo "[Vagrantfile.host_config_linux] USER: Create the ansible user '${ansibleAccount}' if it doesnt exist"
  # Allow sudo to root and access to vBox sharedfolders
  useradd -g users -G wheel,vagrant -d ${homeDir} -s /bin/bash -p $(echo ${ansiblePassword} | openssl passwd -1 -stdin) ${ansibleAccount}
fi 
# These are used by ansible build
echo "${ansiblePassword}" > ${homeDir}/.ansible_password_file
echo "${vaultPassword}" > ${homeDir}/.vault_password_file

echo "[Vagrantfile.host_config_linux] SUDO: Allow passwordless sudo for users in wheel group"
# Important to uncomment NOPASSWD line first
# Preserving escape characters through vagrant assignment
sed -i "s/^# \\(\\%wheel.\\+NOPASSWD\\:.*\\)/\\1/"  /etc/sudoers
sed -i "s/^\\(\\%wheel[[:space:]]\\+ALL=(ALL)[[:space:]]\\+ALL\\)/# \\1/"  /etc/sudoers

# Support ansible pipelineing
sed -i 's/[#[:space:]]*Defaults:[[:space:]]\+\!\?requiretty/Defaults: !requiretty/' /etc/sudoers

# Disable the console TMOUT setting if it exists
# Some long running ansible tasks would be aborted otherwise.
# It will be re-applied by ansible-role.github.hardening
sed -i "s/^TMOUT=.*/TMOUT=0/"  /etc/profile

echo "[Vagrantfile.host_config_linux] SSH KEYS: Copy vagrant ssh key to allow passwordless login"
sshDir="${homeDir}/.ssh"
tmpPrivateKey=${sshDir}/${ansibleAccount}
rsaPrivateKey=${sshDir}/id_rsa
rsaPublicKey=${sshDir}/id_rsa.pub
authorizedKeys=${sshDir}/authorized_keys

mkdir -p ${sshDir}

# Echo the ssh key loaded from windows into target system
# Don't write it directly as it may already exist
echo "${sshPrivateKeyString}" > ${tmpPrivateKey}
chmod 600 ${tmpPrivateKey}

# Extract public key from private key
ssh_pub_key=`ssh-keygen -y -f ${tmpPrivateKey}`

# Has this key been added to authorized_keys already?
if grep -sq "${ssh_pub_key}" ${authorizedKeys}; then
  echo "[Vagrantfile.host_config_linux] SSH keys already provisioned for: ${ansibleAccount}"
else
  echo "[Vagrantfile.host_config_linux] Creating SSH keys for: ${ansibleAccount}"
  mv -f  ${tmpPrivateKey} ${rsaPrivateKey}
  chmod 600 ${rsaPrivateKey}
  
  echo "${ssh_pub_key}" > ${rsaPublicKey}
  chmod 644 ${rsaPublicKey}

  touch ${authorizedKeys}
  echo "${ssh_pub_key}" >> ${authorizedKeys}
  chmod 600 ${authorizedKeys}
fi

# Running as root, so switch created files to ${ansibleAccount} user
chown -R ${ansibleAccount}:users ${homeDir}

# Vagrant images have password login disabled.
# The geck docker image assumes password login.
# Create a copy of devops ssh keys for the root user in the geck container.
sshDirForGeck="${homeDir}/.ssh-geck"
mkdir -p ${sshDirForGeck}
cp -R ${sshDir}/* ${sshDirForGeck} 
chown -R root:root ${sshDirForGeck}

# Vagrant box has password login disabled; but sssd/ad users expect password login.
# Re-enable password login
sed -i "s/^PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
systemctl restart sshd
HOST_CONFIG_LINUX_HEREDOC

# Called from this.configureHost
# Called once per host
# This is run as Administrator
# Minimal setup required to support Ansible.
$host_config_win10 = <<-HOST_CONFIG_WIN10_HEREDOC
# powershell

$vmNetCidr=$args[0]

if ($args.count -ne 1) {
  echo "[ERROR] Invalid paramter count: $($args.count)"
  exit 1
}

echo "[FIREWALL] Allow pings from members of VM network"
# also see ADD_NETWORK_CONFIG_WIN10_HEREDOC
New-NetFirewallRule -DisplayName "Allow inbound ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress ${vmNetCidr} -Action Allow | out-null
New-NetFirewallRule -DisplayName "Allow inbound ICMPv6" -Direction Inbound -Protocol ICMPv6 -IcmpType 8 -RemoteAddress ${vmNetCidr} -Action Allow | out-null

HOST_CONFIG_WIN10_HEREDOC


# Run the ansible-playbook only on the provisioner as the ansible user.
# Cannot run as root because ansible isn't on the path for root.
$run_ansible_playbook = <<-RUN_ANSIBLE_PLAYBOOK_HEREDOC
#!/bin/bash 
set -e
set -u
ansibleAccount=$1
targetBaseName=$2
targetOsFamily=$3
provisionType=$4

echo "######################################################"
echo "[Vagrantfile.run_ansible_playbook] $(hostname)"
echo "######################################################"
echo "    ansibleAccount=${ansibleAccount}"
echo "    targetBaseName=${targetBaseName}"
echo "    targetOsFamily=${targetOsFamily}"
echo "    provisionType =${provisionType}"
echo "    whoami        =$(whoami)"

if [[ $# -ne 4 ]]; then
  echo "[ERROR] Invalid paramter count: $($args.count)"
  exit 1
fi

# Project directory has been copied to VM
if [[ ! -e /etc/ansible/.bootstrapped ]]; then
  echo "######################################################"
  echo "[Vagrantfile.run_ansible_playbook] Calling Makefile target: native-playbook-provisioner-linux"
  # Install Geck on provisioner.
  sudo su - ${ansibleAccount} -c " ( cd /projects/${targetBaseName} && make env_name=vagrant native-playbook-provisioner-linux ) || exit 1 "
fi

echo "######################################################"
echo "[Vagrantfile.run_ansible_playbook] Calling Makefile target: ${provisionType}-playbook-appliance-${targetOsFamily}"
sudo su - ${ansibleAccount} -c "( cd /projects/${targetBaseName} && make env_name=vagrant ${provisionType}-playbook-appliance-${targetOsFamily} ) || exit 1"

RUN_ANSIBLE_PLAYBOOK_HEREDOC


# Called from this.createCluster()
# Runs the ansible configuration scripts on the VM
def configureHost(nodeGroup, machine, clusterDetails, currentHostName, currentVmIp, ansiblePassword, vaultPassword, currentNodeIndex)
  vmNetCidr = "#{clusterDetails['vmBaseIp']}.0/24"
  currentOsFamily = nodeGroup['osFamily']
  # Allows all machines to support ssh login from Virtualbox host
  # Builds should run though jumpbox at 2222
  sshPortForwarded = "22#{currentNodeIndex}"
  rdpPortForwarded = "23#{currentNodeIndex}"
  winrmPortForwarded = "24#{currentNodeIndex}"
  
  # Disable the default folder sync
  machine.vm.synced_folder ".", "/vagrant", disabled: true
  
  if currentOsFamily == 'win10'
    # Windows needs special setup to connect over winrm
    machine.vm.guest = :windows
    machine.vm.communicator = "winrm"
    # FIXME: load password from file
    machine.winrm.password = ansiblePassword
    # Windows install can take a long time and can cause the winrm 'keep alive' to panic and quit
    machine.winrm.retry_limit = 30
    machine.winrm.retry_delay = 10
    if nodeGroup['kerberosEnabled']
      machine.winrm.username = clusterDetails['ldapLogin'] + '@' + clusterDetails['ldapRealm'].downcase
      machine.winrm.transport = :kerberos
    else
      machine.winrm.username = clusterDetails['localLogin']
      machine.winrm.transport = :plaintext
      machine.winrm.basic_auth_only = true
    end
    machine.vm.boot_timeout = 600
    machine.vm.graceful_halt_timeout = 600
    machine.vm.network :forwarded_port, guest: 3389, host: rdpPortForwarded, id: "RDP"
    machine.vm.network :forwarded_port, guest: 5985, host: winrmPortForwarded, id: "winrm", auto_correct: true
  else
    # Prevent port clashes by moving ssh port to unique port number
    machine.vm.network :forwarded_port, guest: 22, host: sshPortForwarded, id: "ssh"
  end


  targetOsFamily = ''
  appHostnameBase = ''
  provisionType = 'geck'
  # CONFIGURE NETWORK ROUTING FROM THIS VM TO ALL OTHER VM IN CLUSTER
  # Add route and /etc/hosts entries for all other nodes in cluster
  # This is primarily because Vagrant hihacks eth0 for NAT connections.
  clusterDetails['nodeGroups'].each do |targetNodeType|
    (0..targetNodeType['nodeCount']-1).each do |targetNodeIndex|
      targetHostName = "#{targetNodeType['hostnameBase']}-#{targetNodeType['addrStart'] + targetNodeIndex}"
      if targetNodeType['hostnameArray'] and ((targetNodeType['hostnameArray']).length == targetNodeType['nodeCount'])
        targetHostName = "#{targetNodeType['hostnameArray'][targetNodeIndex]}"
      end
      targetVmIp = "#{clusterDetails['vmBaseIp']}.#{targetNodeType['addrStart'] + targetNodeIndex}"
      targetNatBaseIp = "#{clusterDetails['natBaseIp']}.#{targetNodeType['addrStart'] + targetNodeIndex}"
      # Vagrant hard coded address
      targetNatIp = "#{targetNatBaseIp}.15"
      targetNatNetIp = "#{targetNatBaseIp}.0"
      targetNatNetCidr = "#{targetNatNetIp}/#{clusterDetails['natNetCidrMask']}"
      targetNatNetMask = "#{clusterDetails['natNetAddrMask']}"
      ldapRealm = "#{clusterDetails['ldapRealm']}"
      
      if targetHostName != currentHostName
        machine.vm.provision  "shell" do |bash_shell|
          if currentOsFamily == 'linux'
            # Call network configuration function for linux (declared above)
            bash_shell.inline = $network_config_linux
          else
            # Call network configuration function for Windows (declared above)
            bash_shell.inline = $network_config_win10
          end
          bash_shell.args = "#{currentVmIp} #{targetHostName} #{targetNatIp} #{targetNatNetCidr} #{targetNatNetIp} #{targetNatNetMask} #{targetVmIp} #{ldapRealm}"
        end
      end
    end
    if targetNodeType['nodeGroup'] == 'appliance'
      targetOsFamily = targetNodeType['osFamily']
      appHostnameBase = targetNodeType['hostnameBase']
      if targetNodeType['provisionType']
        provisionType = targetNodeType['provisionType']
      end
    end
  end

  # Configure ALL hosts to support ansible connections.
  machine.vm.provision  "shell" do |bash_shell|
    if currentOsFamily == 'linux'
      ansibleUsername = clusterDetails['localLogin']
      # Dollars in passwords cause problems; escape them.
      escapedVagrantPassword = Shellwords.escape(vaultPassword)
      escapedAnsiblePassword = Shellwords.escape(ansiblePassword)
      
      bash_shell.inline = $host_config_linux
      bash_shell.args = "#{ansibleUsername} #{escapedAnsiblePassword} #{escapedVagrantPassword}"
    else
      # TODO: Shouldn't assume Windows if not Linux!
      bash_shell.inline = $host_config_win10
      bash_shell.privileged = false
      bash_shell.args = "#{vmNetCidr}"
    end
  end

  # Only the provisioner runs ansible
  if clusterDetails['provisionerHostname'] == currentHostName
    machine.vm.synced_folder ".", "/projects/#{appHostnameBase}", automount: true, mount_options: ["dmode=770,fmode=660"]
    machine.vm.provision  "shell" do |bash_shell|
      bash_shell.inline = $run_ansible_playbook
      bash_shell.privileged = false
      bash_shell.args = "#{clusterDetails['localLogin']} '#{appHostnameBase}' '#{targetOsFamily}' '#{provisionType}'"
    end
  end

end

# Called from project ../../Vagrantfile
# Create a VM for each node declared by clusterDetails.nodeGroups (normally just a provisioner and an appliance )
def createCluster(clusterDetails)
  vault_password   = File.read( ENV['HOME'] + "/.vault_password_file")
  ansible_password = File.read( ENV['HOME'] + "/.ansible_password_file")
  

  Vagrant.configure("2") do |config|
    # always use Vagrants insecure key
    config.ssh.insert_key = false
    # forward ssh agent to easily ssh into the different machines
    config.ssh.forward_agent = true

    clusterDetails['nodeGroups'].each do |nodeGroup|
      (0..nodeGroup['nodeCount']-1).each do |nodeIndex|
	    currentNodeIndex= nodeGroup['addrStart'] + nodeIndex
        currentNodeName = "#{nodeGroup['hostnameBase']}-#{currentNodeIndex}"
        if nodeGroup['hostnameArray'] and ((nodeGroup['hostnameArray']).length == nodeGroup['nodeCount'])
          currentNodeName = "#{nodeGroup['hostnameArray'][nodeIndex]}"
        end
        currentNodeVersion = nodeGroup['imageVersion']
        if nodeGroup['parentBuildNumber']
          currentNodeVersion = nodeGroup['imageVersion'] + '.' + nodeGroup['parentBuildNumber']
        end
        
        currentHostCidr = "#{clusterDetails['natBaseIp']}.#{nodeGroup['addrStart'] + nodeIndex}.0/#{clusterDetails['natNetCidrMask']}"
        currentVmIp = "#{clusterDetails['vmBaseIp']}.#{nodeGroup['addrStart'] + nodeIndex}"
        currentVmNetMask = "255.255.255.0"
        
        config.vm.define "#{currentNodeName}" do |machine|
          machine.vm.box = nodeGroup['imageName']
          machine.vm.box_version = currentNodeVersion
          machine.vm.hostname = currentNodeName
          # eth1: Create a nic to talk to other VMs
          machine.vm.network "private_network", ip: currentVmIp, :netmask => currentVmNetMask
          # Virtualbox specific stuff
          machine.vm.provider clusterDetails['vmProvider'] do |provider_vm|
            provider_vm.name = currentNodeName
            provider_vm.memory = nodeGroup['memory']
            provider_vm.cpus = nodeGroup['cpu']
            # eth0: Modify network address for default NAT nic created by vagrant.
            #       Otherwise vagrant would make all nodes 10.0.2.15, which confuses kubeadm
            provider_vm.customize ['modifyvm',:id, '--natnet1', "#{currentHostCidr}"]
          end
          # Clean VM has been created, now run ansible configuration on it.
          configureHost(nodeGroup, machine, clusterDetails, currentNodeName, currentVmIp, ansible_password, vault_password, currentNodeIndex)
        end
      end
    end
  end
  
end