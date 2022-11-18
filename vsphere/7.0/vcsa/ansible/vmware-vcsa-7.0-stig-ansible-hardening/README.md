# vmware-vcsa-7.0-stig-ansible-hardening
VMware vSphere vCenter Appliance 7.0 STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 4: 28 October 2022  
STIG Type: STIG Readiness Guide  

## Requirements
- Tested with Ansible 2.12.4
- Tested with vCenter 7.0 U3d
- Ansible cannot be run from Windows so you will need a Linux box or load the Linux Subsystem for Windows 10 to run an Unbuntu box for example

## Status
Complete Components

- EAM
- Lookup
- Perfcharts
- vPostgres
- rhttpproxy
- STS
- VAMI
- vsphere-ui

This playbook does not cover the vSphere (ESXi,VM,vCenter) which are in a companion PowerCLI.

## Playbook Structure
Using the EAM role as an example...  

- playbook.yml - Main playbook to run
- /roles/eam/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/eam/handlers/main.yaml - handlers referenced in the photon task
- /roles/eam/tasks/main.yml - Default role playbook
- /roles/eam/tasks/photon.yml - Photon STIG playbook
- /roles/eam/templates/audit.STIG.rules.j2 - Auditd rules file template
- /roles/eam/templates/issue.j2 - Issue file template with DoD login banner
- /roles/eam/templates/umask.sh.j2 - umask.sh file template
- /roles/eam/vars/main.yml - variables reference by photon task.  Update these variables as needed for your environment.

## How to run

Run all controls on a single host. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yaml -k -v  
```

Run all controls on a single host in check mode and does not change anything. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yaml -k -v --check  
```

Run all controls on a single host and only for a specific control VCUI-70-000001. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yaml -k -v --tags VCUI-70-000001  
```

Run all controls on a single host and only for a specific group of controls for ssh. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yaml -k -v --tags sshd  
```

## STIG Control Coverage

- Enabled means the playbook will run it by default 
- Manual means it is either a policy control or a technical control that must be manually addressed due do its need for human review
- The version columns note that a control is compliant out of the box for that version

|     STIG ID    |      Enabled?      |       Manual?      |    Default U1d?    |    Default U2b?    |
|:--------------:|:------------------:|:------------------:|:------------------:|:------------------:|
| VCEM-70-000001 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000002 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000003 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000004 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000005 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000006 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000007 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000008 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000009 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000010 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000011 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000012 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000013 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000014 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000015 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000016 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000017 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000018 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000019 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000020 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000021 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCEM-70-000022 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000023 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000024 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000025 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000026 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCEM-70-000027 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000028 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000029 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000030 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000031 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000032 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCEM-70-000033 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000001 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000002 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000003 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000004 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000005 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000006 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000007 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000008 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000009 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000010 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000011 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000012 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000013 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000014 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000015 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000016 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000017 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000018 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000019 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000020 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000021 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000022 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000023 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000024 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCLU-70-000025 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000026 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000027 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000028 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000029 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000030 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLU-70-000031 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCPF-70-000001 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000002 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000003 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000004 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000005 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000006 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000007 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000008 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000009 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000010 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000011 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000012 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000013 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000014 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000015 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000016 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000017 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000018 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCPF-70-000019 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000020 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000021 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCPF-70-000022 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000023 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000024 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000025 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000026 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCPF-70-000027 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000028 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000029 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000030 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000031 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000032 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000033 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPF-70-000034 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000001 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000002 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCPG-70-000003 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000004 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000005 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000006 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000007 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000008 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000009 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000010 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000011 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000012 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000013 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000014 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000015 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000016 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000017 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000018 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000019 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCPG-70-000020 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCRP-70-000001 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCRP-70-000002 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCRP-70-000003 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCRP-70-000004 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCRP-70-000005 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCRP-70-000006 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCRP-70-000007 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCRP-70-000008 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000001 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000002 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000003 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000004 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000005 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCST-70-000006 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000007 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000008 |         :x:        | :heavy_check_mark: | :heavy_check_mark: |         :x:        |
| VCST-70-000009 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000010 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000011 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000012 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCST-70-000013 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000014 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000015 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000016 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000017 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000018 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCST-70-000019 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000020 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCST-70-000021 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCST-70-000022 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000023 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000024 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000025 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000026 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000027 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000028 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000029 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000030 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCST-70-000031 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000001 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000002 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000003 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000004 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000005 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000006 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000007 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000008 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000009 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000010 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000011 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000012 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000013 | :heavy_check_mark: |         :x:        |         :x:        | :heavy_check_mark: |
| VCLD-70-000014 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000015 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000016 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000017 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000018 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000019 | :heavy_check_mark: |         :x:        |         :x:        | :heavy_check_mark: |
| VCLD-70-000020 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000021 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000022 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000023 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000024 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000025 | :heavy_check_mark: |         :x:        |         :x:        | :heavy_check_mark: |
| VCLD-70-000026 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCLD-70-000027 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000001 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000002 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000003 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000004 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000005 | :heavy_check_mark: |         :x:        | :heavy_check_mark: |         :x:        |
| VCUI-70-000006 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000007 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCUI-70-000008 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000009 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000010 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000011 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000012 | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
| VCUI-70-000013 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000014 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000015 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000016 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000017 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000018 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000019 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000020 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000021 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000022 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000023 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000024 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000025 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000026 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000027 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000028 |         :x:        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000029 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000030 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000031 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000032 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
| VCUI-70-000033 | :heavy_check_mark: |         :x:        | :heavy_check_mark: | :heavy_check_mark: |


## License
Copyright 2020-2021 VMware, Inc.  
SPDX-License-Identifier: Apache-2.0  
