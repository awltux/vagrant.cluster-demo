# Include constants created by makefile
require_relative 'target/Vagrantfile'

# Define the cluster of VMs required
clusterDetails = {
  :vm_provider => 'virtualbox',
  :vmBaseIp => '172.28.128',
  :natBaseIp => '10.150',
  :natNetCidrMask => '24',
  :natNetAddrMask => '255.255.255.0',
  :nodeTypes => [
    { 
      :osFamily => "win10",
      :kerberosEnabled => false,
      :imageName => "inclusivedesign/windows10-eval",
      :imageVersion => "0.4.7",
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
      # CHECK FOR NEW IMAGES HERE: https://app.vagrantup.com/centos/boxes/7
      :imageVersion => "1812.01",
      :hostnameBase => "devops-",
      :addrStart => 20,
      :count => 2,
      :memory => 2048,
      :cpu => 1
    }
  ]
}

require_relative 'Vagrantfile'

createCluster(clusterDetails)