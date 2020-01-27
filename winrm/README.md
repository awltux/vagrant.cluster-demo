# Ansible needs a version of Win2016 that it can safetly connect to in AWS.
# Prior to having an Domain Controller, Win RM provides CredSSP.
# Without ElasticIP, AWS instances start with a new IP address and hostname after each re-boot.
# A CA signed cert is expected to encrypt the WinRM/CredSSP transport.

# Create an AMI that encapsulates the one-off WinRM and PKI setup
# Create a Win 2016 instance
# RDP Connect to the instance with a drive mounted that contains this project.

# Allow scripts to run
Set-ExecutionPolicy Bypass -Scope Process -Force

#Create a password file
echo 'VERY_SECURE_PASSWORD' > ~\.USERPASSWORD
#or set and environment variable
$env:USERPASSWORD = 'VERY_SECURE_PASSWORD'

# Run the ansible-playbook.common-scripts\winrm\aws_winrm_setup_ami.ps1
.\aws_winrm_setup_ami.ps1


