# vmware-cloud-foundation-sddcmgr-5x-stig-ansible-hardening
VMware Cloud Foundation SDDC Manager 5.x Appliance STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 3: July 23, 2024  
STIG Type: STIG Readiness Guide  

## Overview
This is a hardening playbook that utilizes Ansible to perform automated remediation for STIG compliance of the VMware Cloud Foundation SDDC Manager 5.x Appliance STIG Readiness Guide.  

## Supported Versions
- VCF 5.2  

## !!Important!!
- Please read through the README carefully and familiarize yourself with the playbook and ansible before running this playbook
- As always please ensure you have a back out plan if needed you can roll back the changes
- In order to run the Photon role it must be installed as a role so that this playbook may find it
- This playbook has not been tested for forward or backward compatibility beyond the version of SDDC Manager listed under requirements.

## Requirements
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/index.html) installed on a machine that can SSH to the target node(s).  Tested with Ansible 2.14.4.
- SSH enabled and root access enabled
- an API bearer token is needed for the SDDC Manager Application controls to make API calls and needs to be provided at the CLI or vars file

## Playbook Structure

- playbook.yml - Main playbook to run
- requirements.yml - Requirements file for installing dependencies or other roles included in this playbook
- vars-vcenter-example.yml - Example vars file to profile variable values to the playbook for use during execution
- /roles/\<role name>/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/\<role name>/handlers/main.yaml - handlers referenced in the tasks
- /roles/\<role name>/tasks/main.yml - Default role task file
- /roles/\<role name>/templates - Any template files used in the role
- /roles/\<role name>/vars/main.yml - variables referenced by tasks.  Update these variables as needed for your environment.

## How to run

Run all controls on a target appliance. Prompts for user password, displays verbose output, and specifies a vars files to pass variables to the playbook  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --extra-vars @vars-sddcmgr-example.yml
```
Run controls for one service by specifying a tag.  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --extra-vars @vars-sddcmgr-example.yml --tags ui
```
Run a specific control by specifying a tag.  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --extra-vars @vars-sddcmgr-example.yml --tags CFCS-5X-000031
```

## Misc
- If vars need to be updated we recommend either creating a vars file to specify at the command line or adding them to the main playbook.yml or your own playbook.yml so that it is easy to track what is being altered from the original state.  
- Requirements can be installed by running
```
ansible-galaxy roles install -r requirements.yml
```