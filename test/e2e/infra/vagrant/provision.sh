#!/usr/bin/env bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

pushd $THIS_DIR

# With --provision we ensure that we provision the VM again  even if it already
# exists and was already provisioned. Our Ansible playbook ensures that we only
# run tasks that need to be run.
time vagrant up --provision
echo "Writing Vagrant ssh config to file"
vagrant ssh-config > ssh-config
