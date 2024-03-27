# vmware-vcsa-7.0-stig-ansible-hardening
VMware vSphere vCenter Appliance 7.0 STIG Ansible Playbook  
Version: Version 1 Release 2: 26 July 2023  
STIG Type: Official STIG  

## !!Important!!
- Please read through the README carefully and familiarize yourself with the playbook and ansible before running this playbook
- As always please ensure you have a back out plan if needed you can roll back the changes
- This playbook does not cover the vSphere (ESXi,VM,vCenter) which are in a companion PowerCLI script
- In order to run the Photon role it must be installed as a role so that this playbook may find it
- This playbook has not been tested for forward or backward compatibility beyond the version of vCenter listed under requirements. If running on a different version be aware some things may not work

## Requirements
- Tested with Ansible 2.14.4
- Tested with vCenter 7.0 U3n
- Supports 7.0 U3h and newer. Older versions should be updated before running this playbook.
- Ansible cannot be run from Windows so you will need a Linux box or load the Linux Subsystem for Windows 10/11 to run an Ubuntu box for example

## Playbook Structure
Under the roles folder there is a role for each vCenter Appliance component each with their own tasks, handlers, and vars  
  
The EAM role for example has the following files:  

- /roles/eam/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/eam/handlers/main.yaml - handlers referenced in tasks
- /roles/eam/tasks/main.yml - Default role task
- /roles/eam/tasks/eam.yml - Role task
- /roles/eam/vars/main.yml - variables reference by the task

## How to run

If needed update the provided inputs-vcenter-xx.yml file example with any needed variable changes including for the Photon role  

Run all controls on a single host with the provided vars file. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yaml -k -v --extra-vars @vars-vcenter-7.0-example.yml
```

Run all controls on a single host with the provided vars file and only for a specific control VCUI-70-000001. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yaml -k -v --extra-vars @vars-vcenter-7.0-example.yml --tags VCUI-70-000001
```

Run all controls on a single host with the provided vars file and only for a specific group of controls for ssh. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yaml -k -v --extra-vars @vars-vcenter-7.0-example.yml --tags sshd  
```

## License
Copyright 2020-2021 VMware, Inc.  
SPDX-License-Identifier: Apache-2.0  
