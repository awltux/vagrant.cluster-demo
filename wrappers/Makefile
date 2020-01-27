# A set of commands that are useful to remember
# List available targets
# > make [BUILD_NUMBER=003] [list] 

# Environment (default=vagrant) to deploy to
# Loads inventory file from environments/$(environment)/hosts
export environment
# Make arguments need to be exported to make them accessible to included makefile 
# BUILD_NUMBER only used by vagrant-upload
export BUILD_NUMBER

ifneq (,$(wildcard ./scripts/ansible-playbook.common-scripts/Makefile))
include scripts/ansible-playbook.common-scripts/Makefile
else
# The first time the project is cloned, the submodules are empty.
# This will poplulate the submodule when 'make' is called
@no_targets__: git-init
endif

# Initialise the git login helper and initialise/update the submodules
git-init:
	git config --global credential.helper wincred 'cache --timeout 7200'; \
	git submodule init; \
	git submodule update