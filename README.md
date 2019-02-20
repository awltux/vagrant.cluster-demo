# vagrant.cluster-demo
Creates multiple VMs from a JSON configuration file that can be 
provisioned using ansible from a jumpbox. This was intended as test infrastructure
for a Kubernetes test cluster; Win10 support was later added to support Win10 build 
nodes for Jenkins.  
The JSON configuration file can be used to feed information to other build tools.
* jq - command line json parser can be used to create ansible inventory
Currently it creates Win10 and CentOS VM's.
A single VM in the 'provisioner' group is used as a jumpbox for ansible.
The Vagrantfile takes care if network routing and static DNS entries which
allow each VM to communicate with each other over a private network.
Each VM can be accessed over a NAT network from the host (if a NAT entry has been
added to VirtualBox)

Should work with other providers supported by Vagrant, but un-tested.
