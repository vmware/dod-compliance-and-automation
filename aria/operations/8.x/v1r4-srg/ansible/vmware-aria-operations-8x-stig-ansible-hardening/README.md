# vmware-aria-operations-8x-stig-ansible-hardening
VMware Aria Operations 8.x STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 4:  24 July 2024    
STIG Type: [STIG Readiness Guide](https://confluence.eng.vmware.com/pages/viewpage.action?pageId=1231779155)  
Maintainers: Broadcom 

## Overview
This is a hardening playbook that utilizes Ansible to perform automated remediation for STIG compliance of the VMware Aria Operations 8.x STIG Readiness Guide. 

## Supported Versions
- 8.18

## !!Important!!
- Please read through the README carefully and familiarize yourself with the playbook and ansible before running this playbook
- As always please ensure you have a back out plan if needed you can roll back the changes
- In order to run the Photon role it must be installed as a role so that this playbook may find it
- This playbook has not been tested for forward or backward compatibility beyond the versions listed 

## Requirements
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/index.html) installed on a machine that can SSH to the target node(s).  Tested with Ansible 2.16.9.
- SSH enabled and root access enabled

## Playbook Structure
- playbook.yml - Main playbook to run
- requirements.yml - Requirements file for installing dependencies or other roles included in this playbook
- /roles/\<role name>/defaults/main.yml - Default variable values used during the playbook run. Set these to applicable values for the environment.
- /roles/\<role name>/handlers/main.yaml - Handlers referenced in the tasks
- /roles/\<role name>/tasks/main.yml - Default role task file
- /roles/\<role name>/tasks/\<role name>.yml - Tasks used during playbook run.
- /roles/\<role name>/templates - Any template files used in the role.
- /roles/\<role name>/vars/main.yml - variables referenced by tasks.  Update these variables as needed for your environment.

## How to run

Run all controls on a target appliance. Prompts for user password and displays verbose output.
```
ansible-playbook -i 'IP or FQDN', -u 'root' playbook.yml -k -v
```
Run controls for one service by specifying a tag.  
```
ansible-playbook -i 'IP or FQDN', -u 'root' playbook.yml -k -v --tags ui
```
Run a specific control by specifying a tag.  
```
ansible-playbook -i 'IP or FQDN', -u 'root' playbook.yml -k -v --tags VRPU-8X-000001
```

## Misc
- If vars need to be updated it is recommended to either create a vars file to specify at the command line or add them to the main playbook.yml or your own playbook.yml so that it is easy to track what is being altered from the original state.  
- Requirements can be installed by running
```
ansible-galaxy roles install -r requirements.yml
```