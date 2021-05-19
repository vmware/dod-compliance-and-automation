# vmware-vcsa-6.7-stig-ansible-hardening
An ansible playbook to harden VMware vCenter Server Appliance 6.7 against the DISA vSphere 6.7 STIG

## Requirements
- VMware vSphere 6.7 DISA STIG Release 1 Version 1
- Tested with Ansible 2.9.6
- Tested with vCenter 6.7 U3m
- Ansible cannot be run from Windows so you will need a Linux box or load the Linux Subsystem for Windows 10 to run an Unbuntu box for example

## Status
Complete Components

- EAM
- Perfcharts
- Photon
- PostGres
- rhttpproxy
- VAMI
- vsphere-client
- vsphere-ui

## Playbook Structure
Using the Photon role as an example...  

- vcsa-stig.yml - Main playbook to run
- /roles/photon/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/photon/handlers/main.yaml - handlers referenced in the photon task
- /roles/photon/tasks/main.yml - Default role playbook
- /roles/photon/tasks/photon.yml - Photon STIG playbook
- /roles/photon/templates/audit.STIG.rules.j2 - Auditd rules file template
- /roles/photon/templates/issue.j2 - Issue file template with DoD login banner
- /roles/photon/templates/umask.sh.j2 - umask.sh file template
- /roles/photon/vars/main.yml - variables reference by photon task.  Update these variables as needed for your environment.

## How to run

Run all controls on a single host. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' vcsa-stig.yaml -k -v  
```

Run all controls on a single host in check mode and does not change anything. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' vcsa-stig.yaml -k -v --check  
```

Run all controls on a single host and only for a specific control PHTN-OS-000001. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' vcsa-stig.yaml -k -v --tags PHTN-OS-000001  
```

Run all controls on a single host and only for a specific group of controls for ssh. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' vcsa-stig.yaml -k -v --tags sshd  
```

Run all controls on a single host and only for controls tagged 'photon' and also supplies variables at the command line. Prompts for user password and displays verbose output
```
ansible-playbook -i 'IP or FQDN', -u 'username' vcsa-stig.yaml -k -v --tags photon --extra-vars '{"var_syslog_server_name":"test.local","var_syslog_server_port":"514","var_ntp_servers":["time.vmware.com","time2.vmware.com"]}'
```


## Misc
To set syslog or NTP you must update the variables at the top of /roles/photon/vars/main.yml or specifiy then at the command line

Disabling root ssh logins is set to false in the default variables yaml for Photon. You should configure other ssh access besides root before enabling this control if needed.  

PHTN-10-000035 run_sshd_permitrootlogin: false  

## License
Copyright 2019-2020 VMware, Inc.  
SPDX-License-Identifier: Apache-2.0  
