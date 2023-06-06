# vmware-photon-4.0-stig-ansible-hardening
VMware Photon OS 4.0 STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 4: 06 June 2023  
STIG Type: STIG Readiness Guide  

## Requirements
- Tested with Ansible 2.14.4
- Tested with Photon OS 4.0
- Ansible cannot be run from Windows so you will need a Linux box or load the Linux Subsystem for Windows 10 to run an Unbuntu box for example

## Backups
The first item in the photon.yml task is to backup files that may be changed under a folder in the /tmp folder with a timestamp for each ansible run.
This can be turned on/off by updating the create_backups variable to true or false in the defaults main.yml file.

## Playbook Structure

- playbook.yml - Main playbook to run
- /defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /handlers/main.yaml - handlers referenced in the photon task
- /tasks/main.yml - Default role playbook
- /tasks/photon.yml - Photon STIG playbook
- /templates - Files used in template operations
- /vars/main.yml - variables reference by photon task.  Update these variables as needed for your environment.

## How to run

Run all controls on a single host. Prompts for user password, displays verbose output, and uses a vars file for inputs
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --extra-vars @vars-example.yml
```

Run all controls on a single host and only for a specific control PHTN-40-000001. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --tags PHTN-40-000001  
```

Run all controls on a single host and only for controls tagged 'photon' and also supplies variables at the command line. Prompts for user password and displays verbose output
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --tags photon --extra-vars '{"var_syslog_server_name":"test.local","var_syslog_server_port":"514","var_ntp_servers":["time.vmware.com","time2.vmware.com"]}'
```

## Misc
- To set syslog or NTP you must update the variables by specifiying them at the command line or by passing a vars file.
- The DoD SSH banner update is disabled by default. Update the run_etc_issue_dod variable to enable or disable it.
- Steps requiring installs are disabled by default. Enable by setting the following to true: run_rsyslog_install run_openssl_fips_install run_auditd_install run_time_install run_install_aide run_selinux_install
- Enabling FIPS mode for the kernel is disabled by default. Update the run_fips_boot_enable variable to enable or disable it.

## License
Copyright 2019-2021 VMware, Inc.  
SPDX-License-Identifier: Apache-2.0  
