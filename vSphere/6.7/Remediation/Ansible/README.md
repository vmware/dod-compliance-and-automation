# Ansible Playbook for vSphere VCSA 6.7 DISA STIG
Ansible playbook to remediate vSphere VCSA 6.7 DISA STIG Controls

## Requirements
-Draft vSphere 6.7 DISA STIG
-Tested with Ansible 2.8.5
-Tested with vCenter 6.7 U3

## Playbook Structure
Photon role under roles folder so this can be combined with other product specific ansible playbooks.

- photon-stig.yml - Main playbook to run
- README.md - Readme file
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
ansible-playbook -i 'IP or FQDN', -u 'username' photon-stig.yaml -k -v  

Run all controls on a single host in check mode and does not change anything. Prompts for user password and displays verbose output  
ansible-playbook -i 'IP or FQDN', -u 'username' photon-stig.yaml -k -v --check  

Run all controls on a single host and only for a specific control PHTN-OS-000001. Prompts for user password and displays verbose output  
ansible-playbook -i 'IP or FQDN', -u 'username' photon-stig.yaml -k -v --tags PHTN-OS-000001  

Run all controls on a single host and only for a specific group of controls for ssh. Prompts for user password and displays verbose output  
ansible-playbook -i 'IP or FQDN', -u 'username' photon-stig.yaml -k -v --tags sshd  

## Misc
To set syslog or NTP you must update the variables at the top of /roles/photon/vars/main.yml  

Disabling root ssh logins is set to false in the default variables yaml. You should configure other ssh besides root before enabling this control.  
PHTN-10-000035 run_sshd_permitrootlogin: false  

## License
Copyright 2019-2020 VMware, Inc.  
SPDX-License-Identifier: Apache-2.0  