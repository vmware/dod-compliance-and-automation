# vmware-photon-3.0-stig-ansible-hardening
VMware Photon OS 3.0 STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 5: 27 June 2022  
STIG Type: STIG Readiness Guide  

## Requirements
- Tested with Ansible 2.12.4
- Tested with Photon OS 3.0
- Ansible cannot be run from Windows so you will need a Linux box or load the Linux Subsystem for Windows 10 to run an Unbuntu box for example

## Backups
The first item in the photon.yml task is to backup files that may be changed under a folder in the /tmp folder with a timestamp for each ansible run.  
This can be turned on/off by updating the create_backups variable to true or false in the defaults main.yml file.

## Playbook Structure

- playbook.yml - Main playbook to run
- /roles/photon/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/photon/handlers/main.yaml - handlers referenced in the photon task
- /roles/photon/tasks/main.yml - Default role playbook
- /roles/photon/tasks/photon.yml - Photon STIG playbook
- /roles/photon/templates/audit.STIG.rules - Auditd rules file template
- /roles/photon/templates/issue - Issue file template with DoD login banner
- /roles/photon/vars/main.yml - variables reference by photon task.  Update these variables as needed for your environment.

## How to run

Run all controls on a single host. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v  
```

Run all controls on a single host and also supply variables at the command line via a vars file. Prompts for user password and displays verbose output
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --tags photon --extra-vars @vars-vcenter-7.0.yml
```

Run all controls on a single host and only for a specific control PHTN-OS-000001. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --tags PHTN-30-000001  
```

Run all controls on a single host and only for a specific group of controls for ssh. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --tags sshd  
```

Run all controls on a single host and only for controls tagged 'photon' and also supplies variables at the command line. Prompts for user password and displays verbose output
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --tags photon --extra-vars '{"var_syslog_server_name":"test.local","var_syslog_server_port":"514","var_ntp_servers":["time.vmware.com","time2.vmware.com"]}'
```

## Misc
To set syslog or NTP you must update the variables by specifiying them at the command line or by passing a vars file.

The DoD SSH banner update is disabled by default. Update the run_sshd_banner_issue variable to enable or disable it.

Enabling FIPS mode for the kernel is disabled by default. Update the run_fips_kernel variable to enable or disable it.

## STIG Control Coverage

- Enabled means the playbook will run it by default 
- Manual means it is either a policy control or a technical control that must be manually addressed due do its need for human review 

|     STIG ID    |      Enabled?      |       Manual?      |
|:--------------:|:------------------:|:------------------:|
| PHTN-30-000001 | :heavy_check_mark: |         :x:        |
| PHTN-30-000002 | :heavy_check_mark: |         :x:        |
| PHTN-30-000003 |         :x:        |         :x:        |
| PHTN-30-000004 | :heavy_check_mark: |         :x:        |
| PHTN-30-000005 | :heavy_check_mark: |         :x:        |
| PHTN-30-000006 | :heavy_check_mark: |         :x:        |
| PHTN-30-000007 | :heavy_check_mark: |         :x:        |
| PHTN-30-000008 | :heavy_check_mark: |         :x:        |
| PHTN-30-000009 | :heavy_check_mark: |         :x:        |
| PHTN-30-000010 | :heavy_check_mark: |         :x:        |
| PHTN-30-000011 | :heavy_check_mark: |         :x:        |
| PHTN-30-000012 | :heavy_check_mark: |         :x:        |
| PHTN-30-000013 | :heavy_check_mark: |         :x:        |
| PHTN-30-000014 | :heavy_check_mark: |         :x:        |
| PHTN-30-000015 | :heavy_check_mark: |         :x:        |
| PHTN-30-000016 | :heavy_check_mark: |         :x:        |
| PHTN-30-000017 | :heavy_check_mark: |         :x:        |
| PHTN-30-000018 | :heavy_check_mark: |         :x:        |
| PHTN-30-000019 | :heavy_check_mark: |         :x:        |
| PHTN-30-000020 | :heavy_check_mark: |         :x:        |
| PHTN-30-000021 | :heavy_check_mark: |         :x:        |
| PHTN-30-000022 | :heavy_check_mark: |         :x:        |
| PHTN-30-000023 | :heavy_check_mark: |         :x:        |
| PHTN-30-000024 | :heavy_check_mark: |         :x:        |
| PHTN-30-000025 | :heavy_check_mark: |         :x:        |
| PHTN-30-000026 |         :x:        | :heavy_check_mark: |
| PHTN-30-000027 | :heavy_check_mark: |         :x:        |
| PHTN-30-000028 | :heavy_check_mark: |         :x:        |
| PHTN-30-000029 | :heavy_check_mark: |         :x:        |
| PHTN-30-000030 | :heavy_check_mark: |         :x:        |
| PHTN-30-000031 |         :x:        | :heavy_check_mark: |
| PHTN-30-000032 | :heavy_check_mark: |         :x:        |
| PHTN-30-000033 |         :x:        | :heavy_check_mark: |
| PHTN-30-000035 | :heavy_check_mark: |         :x:        |
| PHTN-30-000036 | :heavy_check_mark: |         :x:        |
| PHTN-30-000037 | :heavy_check_mark: |         :x:        |
| PHTN-30-000038 | :heavy_check_mark: |         :x:        |
| PHTN-30-000039 | :heavy_check_mark: |         :x:        |
| PHTN-30-000040 | :heavy_check_mark: |         :x:        |
| PHTN-30-000041 | :heavy_check_mark: |         :x:        |
| PHTN-30-000042 | :heavy_check_mark: |         :x:        |
| PHTN-30-000043 | :heavy_check_mark: |         :x:        |
| PHTN-30-000044 | :heavy_check_mark: |         :x:        |
| PHTN-30-000045 | :heavy_check_mark: |         :x:        |
| PHTN-30-000046 | :heavy_check_mark: |         :x:        |
| PHTN-30-000047 | :heavy_check_mark: |         :x:        |
| PHTN-30-000048 | :heavy_check_mark: |         :x:        |
| PHTN-30-000049 | :heavy_check_mark: |         :x:        |
| PHTN-30-000050 | :heavy_check_mark: |         :x:        |
| PHTN-30-000051 | :heavy_check_mark: |         :x:        |
| PHTN-30-000054 | :heavy_check_mark: |         :x:        |
| PHTN-30-000055 | :heavy_check_mark: |         :x:        |
| PHTN-30-000056 | :heavy_check_mark: |         :x:        |
| PHTN-30-000057 | :heavy_check_mark: |         :x:        |
| PHTN-30-000058 | :heavy_check_mark: |         :x:        |
| PHTN-30-000059 | :heavy_check_mark: |         :x:        |
| PHTN-30-000060 | :heavy_check_mark: |         :x:        |
| PHTN-30-000061 | :heavy_check_mark: |         :x:        |
| PHTN-30-000062 | :heavy_check_mark: | :heavy_check_mark: |
| PHTN-30-000064 | :heavy_check_mark: |         :x:        |
| PHTN-30-000065 | :heavy_check_mark: |         :x:        |
| PHTN-30-000066 | :heavy_check_mark: |         :x:        |
| PHTN-30-000067 | :heavy_check_mark: |         :x:        |
| PHTN-30-000068 | :heavy_check_mark: |         :x:        |
| PHTN-30-000069 | :heavy_check_mark: |         :x:        |
| PHTN-30-000070 | :heavy_check_mark: |         :x:        |
| PHTN-30-000071 | :heavy_check_mark: |         :x:        |
| PHTN-30-000072 | :heavy_check_mark: |         :x:        |
| PHTN-30-000073 | :heavy_check_mark: |         :x:        |
| PHTN-30-000074 | :heavy_check_mark: |         :x:        |
| PHTN-30-000075 | :heavy_check_mark: |         :x:        |
| PHTN-30-000076 | :heavy_check_mark: |         :x:        |
| PHTN-30-000078 | :heavy_check_mark: |         :x:        |
| PHTN-30-000079 | :heavy_check_mark: |         :x:        |
| PHTN-30-000080 | :heavy_check_mark: |         :x:        |
| PHTN-30-000081 | :heavy_check_mark: |         :x:        |
| PHTN-30-000082 | :heavy_check_mark: |         :x:        |
| PHTN-30-000083 | :heavy_check_mark: |         :x:        |
| PHTN-30-000084 | :heavy_check_mark: |         :x:        |
| PHTN-30-000085 | :heavy_check_mark: |         :x:        |
| PHTN-30-000086 | :heavy_check_mark: |         :x:        |
| PHTN-30-000087 | :heavy_check_mark: |         :x:        |
| PHTN-30-000088 | :heavy_check_mark: |         :x:        |
| PHTN-30-000089 | :heavy_check_mark: |         :x:        |
| PHTN-30-000090 | :heavy_check_mark: |         :x:        |
| PHTN-30-000091 | :heavy_check_mark: |         :x:        |
| PHTN-30-000092 | :heavy_check_mark: |         :x:        |
| PHTN-30-000093 | :heavy_check_mark: |         :x:        |
| PHTN-30-000094 |         :x:        | :heavy_check_mark: |
| PHTN-30-000095 | :heavy_check_mark: |         :x:        |
| PHTN-30-000096 | :heavy_check_mark: |         :x:        |
| PHTN-30-000097 | :heavy_check_mark: |         :x:        |
| PHTN-30-000098 | :heavy_check_mark: |         :x:        |
| PHTN-30-000099 | :heavy_check_mark: |         :x:        |
| PHTN-30-000100 | :heavy_check_mark: |         :x:        |
| PHTN-30-000101 | :heavy_check_mark: |         :x:        |
| PHTN-30-000102 | :heavy_check_mark: |         :x:        |
| PHTN-30-000103 | :heavy_check_mark: |         :x:        |
| PHTN-30-000104 | :heavy_check_mark: |         :x:        |
| PHTN-30-000105 | :heavy_check_mark: |         :x:        |
| PHTN-30-000106 | :heavy_check_mark: |         :x:        |
| PHTN-30-000107 | :heavy_check_mark: |         :x:        |
| PHTN-30-000108 | :heavy_check_mark: |         :x:        |
| PHTN-30-000109 | :heavy_check_mark: |         :x:        |
| PHTN-30-000110 | :heavy_check_mark: |         :x:        |
| PHTN-30-000111 | :heavy_check_mark: |         :x:        |
| PHTN-30-000112 | :heavy_check_mark: |         :x:        |
| PHTN-30-000113 | :heavy_check_mark: |         :x:        |
| PHTN-30-000114 | :heavy_check_mark: |         :x:        |
| PHTN-30-000115 | :heavy_check_mark: |         :x:        |
| PHTN-30-000117 | :heavy_check_mark: |         :x:        |
| PHTN-30-000118 | :heavy_check_mark: |         :x:        |
| PHTN-30-000119 | :heavy_check_mark: |         :x:        |
| PHTN-30-000120 | :heavy_check_mark: |         :x:        |
| PHTN-30-000240 | :heavy_check_mark: |         :x:        |
| PHTN-30-000245 | :heavy_check_mark: |         :x:        |

## License
Copyright 2019-2021 VMware, Inc.  
SPDX-License-Identifier: Apache-2.0  
