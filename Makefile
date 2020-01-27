# A set of commands that are useful to remember
# List available targets
# > make [list] 

# Setting debug
# make BUILD_NUMBER=003 vagrant-reload

# THESE SHOULD BE SET BY INCLUDING MAKEFILE
# jumpbox_hostname = ?

DOWNLOAD_TYPE ?= appliance
# false or empty disable debug messages
SHOW_DEBUG ?= false
profile ?=
env_name ?= vagrant
log_dir ?= target

cluster_details_file ?= clusterDetails.json
devops_private_key ?= ~/.ssh/devops.id_rsa

scm_manager_url = https://devops.scm-manager.local.tmvse.com/scm/git

# Use password files in home before target
# If target/.vault_password_file is part if a mounted folder 
# from windows it has a problematic executable bit set.
ifeq ($(shell test -e ~/.vault_password_file && echo -n yes),yes)
VAGRANT_PASSWORD_FILE := ~/.vault_password_file
else
VAGRANT_PASSWORD_FILE = target/.vault_password_file
endif
$(info VAGRANT_PASSWORD_FILE=$(VAGRANT_PASSWORD_FILE))

# Use password files in home before target
# If target/.vault_password_file is part if a mounted folder 
# from windows it has a problematic executable bit set.
ifeq ($(shell test -e ~/.ansible_password_file && echo -n yes),yes)
ANSIBLE_PASSWORD_FILE := ~/.ansible_password_file
else
ANSIBLE_PASSWORD_FILE = target/.ansible_password_file
endif
$(info ANSIBLE_PASSWORD_FILE=$(ANSIBLE_PASSWORD_FILE))


HIDE_CMD :=
ANSIBLE_DEBUG := -vvvv
# If direct call the default is 'false'
ifeq ($(SHOW_DEBUG),false)
HIDE_CMD := @
ANSIBLE_DEBUG :=
endif 
# If indirect call, it defaults to empty
ifeq ($(SHOW_DEBUG),)
HIDE_CMD := @
ANSIBLE_DEBUG :=
endif
$(info ANSIBLE_DEBUG=$(ANSIBLE_DEBUG))

# 2.8 has some useful windows tasks e.g. win_user_profile
ANSIBLE_VERSION := 2.8.1

# The jq app may not have been installed yet
ifneq (, $(shell which jq))

################################################
$(info Start parsing $(cluster_details_file))
################################################

# Read variables from json file
provisioner_hostname := $(shell jq '.provisionerHostname' $(cluster_details_file) | sed 's/\"//g' )
ldap_login := $(shell jq '.ldapLogin' $(cluster_details_file) | sed 's/\"//g')
ldap_realm := $(shell jq '.ldapRealm' $(cluster_details_file) | sed 's/\"//g')
local_login := $(shell jq '.localLogin' $(cluster_details_file) | sed 's/\"//g')

# APPLIANCE CONFIG
app_hostname_base := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .hostnameBase?' $(cluster_details_file) | sed 's/\"//g' )
app_addr_start := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .addrStart?' $(cluster_details_file) | sed 's/\"//g' )
app_image_type := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .imageType?' $(cluster_details_file) | sed 's/\"//g' )
app_image_name := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .imageName?' $(cluster_details_file) | sed 's/\"//g' )
app_image_version := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .imageVersion?' $(cluster_details_file) | sed 's/\"//g' )
app_parent_build_number := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .parentBuildNumber?' $(cluster_details_file) | sed 's/\"//g' )
app_kerberos_enabled := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .kerberosEnabled?' $(cluster_details_file) | sed 's/\"//g' )
provisionType := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .provisionType?' $(cluster_details_file) | sed 's/\"//g' )
osFamily := $(shell jq '.nodeGroups[] | select(.nodeGroup == "appliance") | .osFamily?' $(cluster_details_file) | sed 's/\"//g' )

# PROVISIONER CONFIG
pro_hostname_base := $(shell jq '.nodeGroups[] | select(.nodeGroup == "provisioner") | .hostnameBase?' $(cluster_details_file) | sed 's/\"//g' )
pro_image_type := $(shell jq '.nodeGroups[] | select(.nodeGroup == "provisioner") | .imageType?' $(cluster_details_file) | sed 's/\"//g' )
pro_image_name := $(shell jq '.nodeGroups[] | select(.nodeGroup == "provisioner") | .imageName?' $(cluster_details_file) | sed 's/\"//g' )
pro_image_version := $(shell jq '.nodeGroups[] | select(.nodeGroup == "provisioner") | .imageVersion?' $(cluster_details_file) | sed 's/\"//g' )
pro_parent_build_number := $(shell jq '.nodeGroups[] | select(.nodeGroup == "provisioner") | .parentBuildNumber?' $(cluster_details_file) | sed 's/\"//g' )
pro_kerberos_enabled := $(shell jq '.nodeGroups[] | select(.nodeGroup == "provisioner") | .kerberosEnabled?' $(cluster_details_file) | sed 's/\"//g' )

################################################
$(info Finished parsing $(cluster_details_file))
################################################

endif

ansible_playbook_dir ?= /projects/$(app_hostname_base)


# SETUP FOR VAGRANT_UPLOAD
app_upload_version := $(app_image_version).$(BUILD_NUMBER)
vm_provider := $(shell jq '.vmProvider' $(cluster_details_file) | sed 's/\"//g')

artifactory_base_url := artifactcentral.local.tmvse.com/artifactory
vagrant_upload_url := $(artifactory_base_url)/vagrant-local
vagrant_api_url := $(artifactory_base_url)/api/vagrant
vagrant_download_url := $(vagrant_api_url)/vagrant-local
vagrant_auth_url := $(vagrant_api_url)/auth

inventory_file ?= environments/$(env_name)/hosts
create_inventory_script := ./scripts/ansible-playbook.common-scripts/create_inventory.sh

winrm_port ?= 5985
winrm_scheme ?= http

$(info app_kerberos_enabled = $(app_kerberos_enabled))

# Always trigger this dependencies
.PHONY: no_targets__ list install-bootstrap-packages create-inventory push-ansible-passwords git-sub-modules-check validate-system vagrant-download vagrant-bootstrap-packages

# Create a default target
@no_targets__: list

# List the make targets
list: validate-system
	$(info List of available make targets:)
	@cat scripts/ansible-playbook.common-scripts/Makefile | grep "^[A-Za-z0-9_-]\+:" | awk '{print $$1}' | sed "s/://g" | sed "s/^/   /g"; \
	cat Makefile | grep "^[A-Za-z_-]\+:" | awk '{print $$1}' | sed "s/://g";

validate-system:
	@awk_version=`awk --version | grep 'GNU Awk ' | sed -e 's/GNU Awk \([0-9]\+\)[0-9\.]\+.*/\1/'`; \
	if [[ $${awk_version} -lt 4 ]]; then \
		echo "[ERROR] awk must be major version 4 or higher"; \
		exit 1; \
	fi

# Create a new set of test VMs
vagrant-up: push-ansible-passwords git-sub-modules-check
	# Docker Desktop conflicts with Virtualbox; must disable Microsoft VM system
	# On Windows install gnuwin32 version of make
	# http://gnuwin32.sourceforge.net/packages/make.htm
	@ ( echo "#################################################" &&\
	echo "## INSTALL VAGRANT PLUGIN: VirtualBox Guest installer" &&\
	echo "#################################################" &&\
	vagrant plugin install vagrant-vbguest &&\
	echo "#################################################" &&\
	echo "## RUNNING VAGRANT UP" &&\
	echo "#################################################" &&\
	vagrant up ) || exit 1

# Delete all the test VMs including the jumpbox VM
vagrant-destroy-all:
	rm -f /etc/ansible/.bootstrapped; \
	for i in `vagrant global-status | grep ' virtualbox ' | grep $(playbook_name) | awk '{ print $$1 }'` ; do vagrant destroy -f $$i ; done

# Delete the target system. Keep jumpbox to speed up development cycle
vagrant-destroy:
	# preserve the jumpbox server and it's squid cache
	( for i in `vagrant global-status | \
  grep ' virtualbox ' | \
  grep $(app_hostname_base)-$(app_addr_start) | \
  grep -v ' $(provisioner_hostname) ' | \
  awk '{ print $$1 }'` ; do vagrant destroy -f $$i ; done &&\
	vagrant ssh -c "sudo rm -f /etc/ansible/.bootstrapped" $(provisioner_hostname) ) || exit 1

# Run just the ansible provisioning on the jumpbox VM
vagrant-reload: push-ansible-passwords git-sub-modules-check
	@( vagrant ssh -c \
  "if [[ ! -e /etc/ansible/.bootstrapped ]]; then \
		sudo -u $(local_login) bash -c 'ssh-keyscan $(app_hostname_base)-$(app_addr_start) | \
		grep ecdsa-sha2 > ~$(local_login)/.ssh/known_hosts &&\
		chmod 600 ~$(local_login)/.ssh/known_hosts'; \
	fi" $(provisioner_hostname) &&\
	vagrant reload --provision $(provisioner_hostname) ) || exit 1

# Upload this vagrant box to the artifactory vagrant repo
vagrant-upload: vagrant-bootstrap-packages
# FIXME: NEED CLOUD-INIT BEFORE THIS WILL WORK
ifndef BUILD_NUMBER
	$(error BUILD_NUMBER is not set)
endif
ifndef NODE_NUMBER
	$(error NODE_NUMBER is not set)
endif
	$(HIDE_CMD)PASSWORD_FILE="$(ANSIBLE_PASSWORD_FILE)"; \
	USER_LOGIN=devopssa; \
	USER_PASSWORD=`cat $${PASSWORD_FILE}`; \
	BOX_NAME=$(app_hostname_base); \
	BOX_PROVIDER=$(vm_provider); \
	BOX_VERSION=$(app_upload_version); \
	VAGRANT_BOX_NAME=$${BOX_NAME}-$${BOX_PROVIDER}-$${BOX_VERSION}.box; \
	VAGRANT_UPLOAD_URL="https://$(vagrant_upload_url)/boxes/$${BOX_NAME}/versions/$${BOX_VERSION}/providers/$${BOX_PROVIDER}.box;box_name=$${BOX_NAME};box_provider=$${BOX_PROVIDER};box_version=$${BOX_VERSION}"; \
	echo "Exporting vagrant box: $${VAGRANT_BOX_NAME}"; \
	vagrant package --output target/$${VAGRANT_BOX_NAME} $${BOX_NAME}-$${NODE_NUMBER} && (\
	echo "Uploading vagrant box to Artifactory:"; \
	echo "    $${VAGRANT_UPLOAD_URL}"; \
	curl -u$${USER_LOGIN}:$${USER_PASSWORD} -T target/$${VAGRANT_BOX_NAME} "$${VAGRANT_UPLOAD_URL}" ); \
	echo "Clean-up intermediary file: target/$${VAGRANT_BOX_NAME}"; \
	rm -f target/$${VAGRANT_BOX_NAME}

vagrant-bootstrap-packages:
ifeq (, $(shell which jq))
	echo "Install missing tool 'jq' using choco"
	exit 1
endif

vagrant-download-setup:
# SETUP FOR VAGRANT_DOWNLOAD
image_type := $(app_image_type)
image_name := $(app_image_name)
download_version := $(app_image_version)
ifdef app_parent_build_number
  ifneq ($(app_parent_build_number),null)
    download_version := $(app_image_version).$(app_parent_build_number)
  endif
endif
ifneq ($(DOWNLOAD_TYPE),'appliance')
  image_name := $(pro_image_name)
  download_version := $(pro_image_version)
  ifdef pro_parent_build_number
    ifneq ($(pro_parent_build_number),null)
      download_version := $(pro_image_version).$(pro_parent_build_number)
    endif
  else
    download_version := $(pro_image_version)
  endif
endif

# Download parent vagrant box from the artifactory vagrant repo
# FIXME: INTERNAL DOWNLOADS NEED CLOUD-INIT BEFORE THIS WILL WORK
vagrant-download: vagrant-download-setup vagrant-bootstrap-packages
	$(warning DOWNLOAD_TYPE=$(DOWNLOAD_TYPE))
ifneq ($(DOWNLOAD_TYPE),none)
	# Only add the box if it isnt already downloaded
	$(HIDE_CMD)INSTALLED_BOX_COUNT=`vagrant box list | grep "$(image_name).*$(vm_provider).*$(download_version)" | wc -l`; \
	if [[ "0" == "$${INSTALLED_BOX_COUNT}" ]]; then \
		$(warning image_type=$(image_type))
		ifeq ($(image_type),external)
			BOX_NAME=$(image_name); \
			BOX_PROVIDER=$(vm_provider); \
			BOX_VERSION=$(download_version); \
			vagrant box add $${BOX_NAME} --box-version $${BOX_VERSION} --provider $${BOX_PROVIDER};
		else
			PASSWORD_FILE="$(ANSIBLE_PASSWORD_FILE)"; \
	USER_LOGIN=devopssa; \
	USER_PASSWORD=`cat $${PASSWORD_FILE}`; \
	BOX_NAME=$(image_name); \
	BOX_PROVIDER=$(vm_provider); \
	BOX_VERSION=$(download_version); \
	VAGRANT_SERVER_BASE_URL=https://$${USER_LOGIN}:$${USER_PASSWORD}@$(vagrant_download_url); \
	VAGRANT_DOWNLOAD_URL="$${VAGRANT_SERVER_BASE_URL}/$${BOX_NAME}"; \
	VAGRANT_SERVER_URL=$${VAGRANT_SERVER_BASE_URL} \
	ATLAS_TOKEN=`curl -s https://$${USER_LOGIN}:$${USER_PASSWORD}@$(vagrant_auth_url)` \
	vagrant box add $${BOX_NAME} --box-version $${BOX_VERSION} $${VAGRANT_DOWNLOAD_URL};
		endif
	fi
endif

# Run the ansible provisioning on all VMs; if target VM is to be re-provisioned after update to Vagrantfile
# NOTE: provisioning is launched from jumpbox VM 
vagrant-reload-all: push-ansible-passwords
	vagrant reload --provision 

vagrant-ssh:
	vagrant ssh -c "sudo su - $(local_login)" $(provisioner_hostname)

# List the machine id's that identify a machine in .vagrant dir.
# Can be used to share VM's between vagrant projects
vagrant-id-list:
	vboxmanage list vms

# Copy the password files from the windows home directory to the projects target dir
push-ansible-passwords:
	@vault_file=~/.vault_password_file; \
	echo "vault_file=$${vault_file}"; \
        # Use the password file from users home by default; \
	if [[ -e $${vault_file} ]]; then \
		vault_target_file="target/.vault_password_file"; \
		if [[ ! -e $${vault_target_file} ]]; then \
			echo "[Makefile.$@] Copying ansible vault password file: $${vault_file}"; \
		mkdir -p target; \
		cp $${vault_file} target/; \
	fi; \
	else \
		echo "[ERROR] Missing password file: `hostname`:$${vault_file}"; \
		exit 1; \
	fi; \
	ansible_file=~/.ansible_password_file; \
	ansible_target_file="target/.ansible_password_file"; \
	if [[ -e $${ansible_file} ]]; then \
		if [[ ! -e $${ansible_target_file} ]]; then \
			echo "[Makefile.$@] Copying Ansible password file: $${ansible_file}"; \
		mkdir -p target; \
		cp $${ansible_file} target/; \
		fi; \
	else \
		echo "[ERROR] Missing password file: `hostname`:$${ansible_file}"; \
		exit 1; \
	fi;

# When running under Vagrant, verify if the standard sub-modules have been populated 
# to support the provisioner VM.
git-sub-modules-check:
	@if [[ ! -d roles/ansible-role.jumpbox/tasks ]]; then \
		echo "[ERROR] Git sub-modules need to exist for a Vagrant environment. Run 'make add-jumpbox-submodules'" && \
		exit 1; \
	fi

# If the inventory file is missing for the requested environment, create 
# a simple one from the clusterDetails.json
create-inventory: install-bootstrap-packages
	@echo "[Makefile.$@] Create an Ansible inventory file" && \
	source $(create_inventory_script) "$(cluster_details_file)" "$(env_name)" "$(inventory_file)"

# Install:
#   jq: to allow 'make' and 'bash' to interpret JSON
#   sshpass: needed by ansible to connect over ssh
#   ansible: from pip becuase yum version has out of date dependencies
#   dnspython: allows hostnames to be resolved by ansible
install-bootstrap-packages:
	# FIXME: Need to add username=$(ldap_login) and password=$(ANSIBLE_PASSWORD_FILE) to /etc/yum.conf: [main] section
	@( sudo yum install -y epel-release &&\
	sudo yum install -y libselinux-python python3 python3-pip jq sshpass &&\
	sudo su - root -c "pip3 install --upgrade pip" &&\
	sudo su - root -c "pip3 install ansible==$(ANSIBLE_VERSION) dnspython requests pywinrm netaddr jmespath selinux" ) || exit 1

# The provisioner provides Docker and GECK so ansible must be run native on linux.
native-playbook-provisioner-linux: install-bootstrap-packages create-inventory
	@( echo "[Makefile.$@] Apply provisioner ansible-playbook" && \
	export ANSIBLE_FORCE_COLOR=true && \
	ansible-playbook \
	--inventory $(inventory_file) \
	--vault-id=$(VAGRANT_PASSWORD_FILE) \
	-e env_name='$(env_name)' \
	ansible-playbook.provisioner.yml 2>&1 ) || ( export RETURN_CODE=$$? && echo "native-playbook-provisioner-linux RC: $$RETURN_CODE"; exit $$RETURN_CODE )
#	ansible-playbook.provisioner.yml 2>&1 | tee $(log_dir)/$@.log 
  
# Initialises a host before it has docker and geck installed
native-playbook-appliance-linux: install-bootstrap-packages create-inventory
	export ANSIBLE_FORCE_COLOR=true && \
	ansible-playbook \
	--inventory $(inventory_file) \
	--vault-id=$(VAGRANT_PASSWORD_FILE) \
	-e env_name='$(env_name)' \
	ansible-playbook.appliance.yml 2>&1 | tee $(log_dir)/$@.log || exit 1

# Initialises a host before it has docker and geck installed
# Ansible connection (esp for windows) is configured in group_vars
native-playbook-appliance-win10: check-profile check-env-name install-bootstrap-packages create-inventory
	$(HIDE_CMD) ansible-playbook \
	--inventory $(inventory_file) \
	--vault-id=$(VAGRANT_PASSWORD_FILE) $(ANSIBLE_DEBUG) \
	-e env_name='$(env_name)' \
	ansible-playbook.appliance.yml \
	-e profile='$(profile)' 2>&1 | tee $(log_dir)/$@.log || exit 1

# Open a geck based environment to develop and test ansible scripts
geck-shell: create-inventory
	baseDir=`pwd`; \
	PLAYBOOK_FILE=ansible-playbook.appliance.yml; \
	sudo yum install -y python-dns; \
	docker run --network host \
	--rm \
	-v ~$(local_login)/.ssh-geck:/root/.ssh:Z \
	-v $${baseDir}:/app/playbook:Z \
	-v $${baseDir}/target/data:/app/data:Z \
	-v $${baseDir}/target/logs:/app/logs:Z \
	-ti \
	--entrypoint /bin/ash \
	geck:latest

# Apply the ansible playbook to the linux target system using geck 
geck-playbook-appliance-linux: create-inventory
	( sudo yum install -y python-dns &&\
	baseDir=`pwd` \
	PLAYBOOK_FILE=ansible-playbook.appliance.yml \
	docker run --network host \
	--rm \
	-v ~$(local_login)/.ssh-geck:/root/.ssh:Z \
	-v $${baseDir}:/app/playbook:Z \
	-v $${baseDir}/target/data:/app/data:Z \
	-v $${baseDir}/target/logs:/app/logs:Z \
	geck:latest \
	-e env_name='$(env_name)' \
	--playbook $${PLAYBOOK_FILE} \
	--inventory $(inventory_file) \
	--vault-id=/app/playbook/target/.vault_password_file 2>&1 | tee $(log_dir)/$@.log ) || exit 1
# Add -vvvv to end of this command to debug

# Apply the ansible playbook to the win10 target system using geck 
geck-playbook-appliance-win10: check-profile create-inventory
ifeq ('$(app_kerberos_enabled)', 'true')
	baseDir=`pwd` &&\
	PLAYBOOK_FILE=ansible-playbook.appliance.yml &&\
	docker run --network host \
	--rm \
	-v ~$(local_login)/.ssh-geck:/root/.ssh:Z \
	-v $${baseDir}:/app/playbook:Z \
	-v $${baseDir}/target/data:/app/data:Z \
	-v $${baseDir}/target/logs:/app/logs:Z \
	geck:latest \
	--playbook $${PLAYBOOK_FILE} \
	--inventory $(inventory_file) \
	--vault-id=/app/playbook/target/.vault_password_file \
	-e env_name='$(env_name)' \
	-e ansible_port=$(winrm_port) \
	-e ansible_connection=winrm \
	-e ansible_winrm_scheme=$(winrm_scheme) \
	-e ansible_user='$(ldap_login)@local.tmvse.com' \
	-e ansible_winrm_transport=kerberos 2>&1 | tee $(log_dir)/$@.log || exit 1
else
	baseDir=`pwd`; \
	PLAYBOOK_FILE=ansible-playbook.appliance.yml; \
	PASSWORD_FILE=$(ANSIBLE_PASSWORD_FILE); \
	ANSIBLE_PASSWORD=`cat $${PASSWORD_FILE}`; \
	docker run --network host \
	--rm \
	-v ~$(local_login)/.ssh-geck:/root/.ssh:Z \
	-v $${baseDir}:/app/playbook:Z \
	-v $${baseDir}/target/data:/app/data:Z \
	-v $${baseDir}/target/logs:/app/logs:Z \
	geck:latest \
	--playbook $${PLAYBOOK_FILE} \
	--inventory $(inventory_file) \
	--vault-id=/app/playbook/target/.vault_password_file \
	-e env_name='$(env_name)' \
	-e ansible_password='$${ANSIBLE_PASSWORD}' \
	-e ansible_port='$(winrm_port)' \
	-e ansible_connection=winrm \
	-e ansible_winrm_scheme=$(winrm_scheme) \
	-e ansible_user='$(local_login)' \
	-e ansible_winrm_transport=plaintext \
	-e ansible_winrm_basic_auth_only=true 2>&1 | tee $(log_dir)/$@.log || exit 1
endif
# Add -vvvv to end of this command to debug

# Store your git credentials in a local file
git-credential-helper:
	$(info Cache your password in ~/.git-credentials. Change to 'memory' if system is not secure/shared )
	git config --global credential.helper store
  
# Pull the latest chnage-sets from origin master.
git-pull-origin-master:
	$(info Pull the latest change-sets from origin master, including sub-modules)
	git pull origin master && \
	git submodule foreach --recursive git pull origin master

# Push any local changes to origin master
git-push-origin-master:
	$(info Push any local changes to origin master)
	git.exe submodule foreach --recursive git push origin master && \
	git.exe push origin master

# This will create a git tag for the complete project, including all of the submodules
# The tag name is a concatenation of the appliance base name and the projects current git commit.
# NOTE: This assumes all changes have been committed amnd pushed.  
git-tag:
	GIT_COMMIT=`git log --pretty=format:'%h' -n 1` && \
	GIT_TAG=$(app_hostname_base)-$${GIT_COMMIT} && \
	git submodule update --init --recursive && \
	git submodule foreach --recursive git tag -m "[TAGGED SUBMODULE] $${GIT_TAG}" $${GIT_TAG} && \
	git tag -m "[TAGGED] $${GIT_TAG}" $${GIT_TAG}

# Passwords used by the scripts are stored in an encrypted vault file called vault/credentials.yml
# If you dont know the devops password to this file, you will need to create a new one.
# This target will try to extract all yml files under the vault directory and stores them 
# in an unencrypted file target/credentials.yml. 
# The file ansible.cfg declares the location of the vault password file e.g. 
#    ${HOME}/.vault_password_file. 
# If this password doesn't unlock the vault files, a template file will be copied to target/credentials.yml.
# Once extracted, modify target/credentials.yml and then call "make vault-encrypt" to update the encrypted vault file.
# LINUX ONLY: This command will only work on a Linux host i.e. provisioner
vault-extract:
	$(HIDE_CMD)if ! ansible-vault view vault/*.yml > target/credentials.yml; then \
	   echo "[TO FIX THIS] Modify target/credentials.yml then use 'make vault_encrypt'" && \
		 cp scripts/ansible-playbook.common-scripts/credentials.yml target/credentials.yml; \
	fi;

# Encrypts the contents of target/credentials.yml to replace vault/credentials.yml
# The file ansible.cfg declares the location of the vault password file e.g. 
#    ${HOME}/.vault_password_file. 
# LINUX ONLY: This command will only work on a Linux host i.e. provisioner
vault-encrypt:
	$(HIDE_CMD)if [[ ! -e $(VAGRANT_PASSWORD_FILE) ]]; then \
	  echo "[ERROR] Missing file: $(VAGRANT_PASSWORD_FILE)" && \
	  exit 1; \
	fi && \
	( cat $(VAGRANT_PASSWORD_FILE) | ansible-vault encrypt --output target/credentials-encrypted.yml target/credentials.yml ) && \
	cp target/credentials-encrypted.yml vault/credentials.yml && \
	rm -f target/credentials-encrypted.yml target/credentials.yml

# Validate that a profile has been defined and that the requested profile has a configuration file
check-profile:
ifeq ($(profile),)
	$(info Select a profile using: make profile=$${profile_name} ... )
	$(info Profile is loaded from: profiles/$${profile_name}/main.yml )
	$(error Missing property: profile)
endif

ifneq ($(shell test -e ./profiles/$(profile)/main.yml && echo -n yes),yes)
	$(error [ERROR] Missing 'profile' file: ./profiles/$(profile)/main.yml)
endif

# Validate that an environment has been defined and that the requested environment has a configuration file
check-env-name:
ifeq ($(env_name),)
	$(info Select a env_name using: make env_name=$${env_name} ... )
	$(info Inventory is loaded from: environments/$${env_name}/hosts )
	$(error Missing property: env_name)
endif

ifneq ($(shell test -e ./environments/$(env_name)/main.yml && echo -n yes),yes)
	$(error [ERROR] Missing 'environment' file: ./environments/$(env_name)/main.yml)
endif

# VAGRANT PROJECT SETUP
# When setting up a new ansible-playbook project, the vagrant build 
# requires a number of submodules to support the provisioner VM.
# This will add all of the required git submodules to your project.
add-jumpbox-submodules:
	@for roleName in \
			ansible-role.jumpbox \
			ansible-role.github.docker-ce \
			ansible-role.centos-system \
			ansible-role.artifactory-client \
			ansible-role.join-ad-realm \
			ansible-role.github.hardening; \
	do \
		if [[ -d roles/$${roleName} ]]; then \
			echo "Nothing to do, role exists: roles/$${roleName}"; \
		else \
		  git submodule add $(scm_manager_url)/$${roleName} roles/$${roleName}; \
		fi; \
	done;
