# aria-suite-lifecycle-8x-stig-ansible-hardening
VMware Aria Suite Lifecycle 8.x Appliance STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 2: 27 February 2024  
STIG Type: STIG Readiness Guide  

## Overview
This is a hardening playbook that utilizes Ansible to perform automated remediation for STIG compliance of the VMware Aria Suite Lifecycle 8.x Appliance STIG Readiness Guide.

## Supported Versions
- VMware Aria Suite Lifecycle 8.14-8.18  

## !!Important!!
- Please read through the README carefully and familiarize yourself with the playbook and Ansible before running this playbook.
- As always please ensure you have a back out plan - if needed you can roll back the changes.
- In order to run the Photon role it must be installed as a role so that this playbook may find it.
- This playbook has not been tested for forward or backward compatibility beyond the version listed under supported versions.

### Requirements
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/index.html) installed on a machine that can SSH to the target node(s).  Tested with Ansible 2.16.4.
- SSH with root access enabled on the target Aria Suite Lifecycle node(s).

## Playbook Structure
- playbook.yml - Main playbook to run
- /roles/\<role name>/defaults/main.yml - Default variables to use during the run of the playbook
- /roles/\<role name>/tasks/main.yml - Default role task file
- /roles/\<role name>/handlers/main.yml - Dependencies for service restarts
- /roles/\<role name>/\<role name>.yml - Task definitions for the role

## How to run

Run all controls on a target appliance. Prompt for password and display verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'root' playbook.yml -k -v -b
```
Run controls for one service by specifying a tag.  
```
ansible-playbook -i 'IP or FQDN', -u 'root' playbook.yml -k -v -b -t nginx
```
Run a specific control by specifying a tag.  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v -b -t VLMN-8X-000019
```

## Misc
- If vars need to be updated we recommend either creating a vars file to specify at the command line or adding them to the main playbook.yml or your own playbook.yml so that it is easy to track what is being altered from the original state.  
