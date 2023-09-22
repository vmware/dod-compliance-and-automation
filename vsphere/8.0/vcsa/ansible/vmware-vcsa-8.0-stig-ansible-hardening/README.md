# vmware-vcsa-8.0-stig-ansible-hardening
VMware vCenter 8.0 Appliance STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 2: September 21, 2023  
STIG Type: STIG Readiness Guide  

## Overview
This is a hardening playbook that utilizes Ansible to perform automated remediation for STIG compliance of the VMware vCenter 8.0 Appliance STIG Readiness Guide.  

## !!Important!!
- Please read through the README carefully and familiarize yourself with the playbook and ansible before running this playbook
- As of 8.0 U2 the vCenter appliance is now based on Photon 4. Using the correct example variables file is required!
- As always please ensure you have a backout plan if needed you can roll back the changes
- This playbook does not cover the vSphere (ESXi,VM,vCenter) which are in a companion PowerCLI script
- In order to run the Photon role it must be installed as a role so that this playbook may find it
- This playbook has not been tested for forward or backward compatibility beyond the version of vCenter listed under requirements.

## Requirements
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/index.html) installed on a machine that can SSH to the target node(s).  Tested with Ansible 2.14.4.
- SSH enabled
- The bash shell will need to be enabled on the vCenter appliance as the default shell for root

## Playbook Structure

- playbook.yml - Main playbook to run
- requirements.yml - Requirements file for installing dependencies or other roles included in this playbook
- vars-vcenter-example.yml - Example vars file to profile variable values to the playbook for use during execution
- /roles/<role name>/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/<role name>/handlers/main.yaml - handlers referenced in the tasks
- /roles/<role name>/tasks/main.yml - Default role task file
- /roles/<role name>/templates - Any template files used in the role
- /roles/<role name>/vars/main.yml - variables referenced by tasks.  Update these variables as needed for your environment.

## How to run

Run all controls on a target vCenter. Prompts for user password, displays verbose output, and specifies a vars files to pass variables to the playbook  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --extra-vars @vars-vcenter-example.yml
```
Run controls for one service by specifying a tag.  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --extra-vars @vars-vcenter-example.yml --tags ui
```
Run a specific control by specifying a tag.  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --extra-vars @vars-vcenter-example.yml --tags VCEM-80-000001
```

## Misc
- If vars need to be updated we recommend either creating a vars file to specify at the command line or adding them to the main playbook.yml or your own playbook.yml so that it is easy to track what is being altered from the original state.  
- Requirements can be installed by running
```
ansible-galaxy roles install -r requirements.yml
```