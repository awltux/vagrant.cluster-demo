
# Load the shared configuration
require 'json'
json_file = File.open "clusterDetails.json"
clusterDetails = JSON.load(json_file)

require_relative 'scripts/ansible-playbook.common-scripts/Vagrantfile'

createCluster(clusterDetails)