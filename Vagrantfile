vm_provider="virtualbox"
nicRoutePath = "/etc/sysconfig/network-scripts/route-eth1"


# :imageVersion FROM HERE: https://app.vagrantup.com/centos/boxes/7
clusterDetails = {
  :vmBaseIp => '172.28.128',
  :natBaseIp => '10.150',
  :natNetCidrMask => '24',
  :natNetAddrMask => '255.255.255.0',
  :nodeTypes => [
    { 
      :osFamily => "win10",
      :kerberosEnabled => false,
      :imageName => "canon/windows10",
      :imageVersion => "0",
      :hostnameBase => "win10-",
      :addrStart => 10,
      :count => 1,
      :memory => 4096,
      :cpu => 2
    },
    { 
      :osFamily => "linux",
      :kerberosEnabled => true,
      :imageName => "centos/7",
      :imageVersion => "1812.01",
      :hostnameBase => "devops-",
      :addrStart => 20,
      :count => 2,
      :memory => 2048,
      :cpu => 1
    }
  ]
}

$add_network_config_linux = <<-ADD_NETWORK_CONFIG_LINUX_HEREDOC
#!/bin/bash -eu

currentVmIp=$1
targetHostName=$2
targetNatIp=$3
targetNatNetCidr=$4
targetNatNetIp=$5
targetNatNetMask=$6
targetVmIp_NOT_USED_FOR_LINUX=$7

if [[ $# -ne 7 ]]; then
  echo "[ERROR] Invalid number of parameters for add_network_config_linux: $#"
  exit 1
fi

if ! grep -q "${targetHostName}" /etc/hosts; then
  echo "${targetNatIp} ${targetHostName}" >> /etc/hosts
fi

if ! ip route | grep "${targetNatNetCidr}"; then
  # Create non-persistent route for current boot
  ip route add ${targetNatNetCidr} via ${currentVmIp}
fi

touch #{nicRoutePath}
if ! grep "^ADDRESS[0-9]\+=${targetNatNetIp}" #{nicRoutePath}; then
  routeCount=$(grep "^ADDRESS.*" #{nicRoutePath} | wc -l )
  # Create persistent route for future boots
  cat >> #{nicRoutePath} <<INNER_HEREDOC
    ADDRESS${routeCount}=${targetNatNetIp}
    NETMASK${routeCount}=${targetNatNetMask}
    GATEWAY${routeCount}=${currentVmIp}
INNER_HEREDOC
fi

ADD_NETWORK_CONFIG_LINUX_HEREDOC

$add_network_config_win10 = <<-ADD_NETWORK_CONFIG_WIN10_HEREDOC
# powershell

$currentVmIp=$args[0]
$targetHostName=$args[1]
$targetNatIp=$args[2]
$targetNatNetCidr=$args[3]
$targetNatNetIp_NOT_USED_FOR_WIN10=$args[4]
$targetNatNetMask_NOT_USED_FOR_WIN10=$args[5]
$targetVmIp=$args[6]

if ($args.count -ne 7) {
  echo "[ERROR] Invalid paramter count: $($args.count)"
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
    echo "Route added for $destinationCidr"
  }
  catch [Microsoft.Management.Infrastructure.CimException] {
    echo "Route already exists for $destinationCidr"
  }
}

function Add-ResolveHost {
  param (
    [Parameter(Mandatory=$true)][String]$ipAddress,
    [Parameter(Mandatory=$true)][String]$hostname
  )
  echo "Check /etc/hosts for: ipAddress=$ipAddress hostname=$hostname"
  $lineToInsert = $ipAddress + '    ' + $hostname
  $filename = "$env:windir\\System32\\drivers\\etc\\hosts"
  $content = Get-Content $filename
  $foundLine=$false

  foreach ($line in $content) {
    if ($line -match ${ipAddress} + '\s+' + ${hostname}) {
      echo "Existing /etc/hosts entry: '$lineToInsert'"
      $foundLine=$true
    }
  }
  if (-not $foundLine) {
    echo "Inserting /etc/hosts entry: '$lineToInsert'"
    $lineToInsert | Out-File -encoding ASCII -append $filename
  }
}

Add-NetRouteByDestination $targetNatNetCidr $currentVmIp $targetVmIp
Add-ResolveHost $targetNatIp $targetHostName

ADD_NETWORK_CONFIG_WIN10_HEREDOC

$ansible_config_win10 = <<-ANSIBLE_CONFIG_WIN10_HEREDOC
# powershell

$currentVmIp=$args[0]
$targetHostName=$args[1]
$targetNatIp=$args[2]
$targetNatNetIp=$args[3]
$targetNatNetCidr=$args[4]
$targetNatNetMask=$args[5]

if ($args.count -ne 6) {
  echo "[ERROR] Invalid paramter count: $args.count"
  exit 1
}

New-NetFirewallRule -DisplayName "Allow inbound ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress $targetNatNetCidr -Action Allow

ANSIBLE_CONFIG_WIN10_HEREDOC

def configureNetworkRouting(clusterDetails, machine, currentHostName, currentVmIp, currentOsFamily)
  # Add route and /etc/hosts entries for all other nodes in cluster
  clusterDetails[:nodeTypes].each do |innerNodeType|
    (0..innerNodeType[:count]-1).each do |innerNodeIndex|
      targetHostName = "#{innerNodeType[:hostnameBase]}#{innerNodeType[:addrStart] + innerNodeIndex}"
      targetVmIp = "#{clusterDetails[:vmBaseIp]}.#{innerNodeType[:addrStart] + innerNodeIndex}"
      targetNatBaseIp = "#{clusterDetails[:natBaseIp]}.#{innerNodeType[:addrStart] + innerNodeIndex}"
      # Vagrant hard coded address
      targetNatIp = "#{targetNatBaseIp}.15"
      targetNatNetIp = "#{targetNatBaseIp}.0"
      targetNatNetCidr = "#{targetNatNetIp}/#{clusterDetails[:natNetCidrMask]}"
      targetNatNetMask = "#{clusterDetails[:natNetAddrMask]}"
      
      if targetHostName != currentHostName
        machine.vm.provision  "shell" do |bash_shell|
          if currentOsFamily == 'linux'
            bash_shell.inline = $add_network_config_linux
          else
            bash_shell.inline = $add_network_config_win10
          end
          bash_shell.args = "#{currentVmIp} #{targetHostName} #{targetNatIp} #{targetNatNetCidr} #{targetNatNetIp} #{targetNatNetMask} #{targetVmIp}"
        end
      end
    end
  end
end

def configureForAnsible(clusterDetails, machine, currentHostName, currentVmIp, currentOsFamily)
#  machine.vm.provision  "shell" do |bash_shell|
#    if currentOsFamily == 'linux'
#      bash_shell.inline = $ansible_config_linux
#    else
#      bash_shell.inline = $ansible_config_win10
#    end
#    bash_shell.args = "#{currentVmIp} #{targetHostName} #{targetNatIp} #{targetNatNetIp} #{targetNatNetCidr} #{targetNatNetMask}"
#  end
end


Vagrant.configure("2") do |config|
  # always use Vagrants insecure key
  config.ssh.insert_key = false
  # forward ssh agent to easily ssh into the different machines
  config.ssh.forward_agent = true
  check_guest_additions = false
  functional_vboxsf = false


  clusterDetails[:nodeTypes].each do |nodeType|
    (0..nodeType[:count]-1).each do |nodeIndex|
      currentNodeName = "#{nodeType[:hostnameBase]}#{nodeType[:addrStart] + nodeIndex}"
      currentHostCidr = "#{clusterDetails[:natBaseIp]}.#{nodeType[:addrStart] + nodeIndex}.0/#{clusterDetails[:natNetCidrMask]}"
      currentVmIp = "#{clusterDetails[:vmBaseIp]}.#{nodeType[:addrStart] + nodeIndex}"
      currentVmNetMask = "255.255.255.0"
      
      config.vm.define "#{currentNodeName}" do |machine|
        machine.vm.box = nodeType[:imageName]
        machine.vm.box_version = nodeType[:imageVersion]
        machine.vm.hostname = "#{currentNodeName}"
        # eth1: Create a nic to talk to other VMs
        machine.vm.network "private_network", ip: "#{currentVmIp}", :netmask => "#{currentVmNetMask}"
        # Virtualbox specific stuff
        machine.vm.provider "#{vm_provider}" do |provider_vm|
          provider_vm.name = "#{currentNodeName}"
          provider_vm.memory = nodeType[:memory]
          provider_vm.cpus = nodeType[:cpu]
          # eth0: Modify network address for default NAT nic created by vagrant.
          #       Otherwise vagrant would make all nodes 10.0.2.15, which confuses kubeadm
          provider_vm.customize ['modifyvm',:id, '--natnet1', "#{currentHostCidr}"] 
        end
        if nodeType[:osFamily] == 'win10'
          machine.vm.guest = :windows
          machine.vm.communicator = "winrm"
          machine.winrm.username = "devops"
          # FIXME: load password from file
          machine.winrm.password = "D3v0ps1sAw3s0m3"
          # Windows install can take a long time and can cause the winrm 'keep alive' to panic and quit
          machine.winrm.retry_limit = 30
          machine.winrm.retry_delay = 10
          if nodeType[:kerberosEnabled]
            machine.winrm.transport = :kerberos
          else
            machine.winrm.basic_auth_only = true
            machine.winrm.transport = :plaintext
          end
          machine.vm.boot_timeout = 600
          machine.vm.graceful_halt_timeout = 600
          machine.vm.network :forwarded_port, guest: 3389, host: 3389
          machine.vm.network :forwarded_port, guest: 5985, host: 55985, id: "winrm", auto_correct: true
        end        
        configureNetworkRouting(clusterDetails, machine, currentNodeName, currentVmIp, nodeType[:osFamily])
#        configureForAnsible(clusterDetails, machine, currentNodeName, currentVmIp, nodeType[:osFamily])
      end
    end
  end
end
