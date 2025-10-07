# vmware-photon-5.0-stig-ansible-hardening
VMware Photon OS 5.0 STIG Readiness Guide Ansible Playbook  
Version: Version 3 Release 2: 01 October 2025  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Requirements
- Tested with Ansible 2.16.3
- Tested with Photon OS 5.0
- Ansible cannot be run from Windows so you will need a Linux box or load the Linux Subsystem for Windows 11 to run an Ubuntu box for example.

## Backups
The first item in the photon.yml task is to backup files that may be changed under a folder in the /tmp folder with a timestamp for each ansible run.
This can be turned on/off by updating the `create_backups` variable to true or false in a vars file provided at the CLI as in the examples.

## Playbook Structure

- playbook.yml - Main playbook to run
- /defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false by providing a vars file at the CLI
- /handlers/main.yaml - handlers referenced in the photon task
- /tasks/main.yml - Default role playbook
- /tasks/photon.yml - Photon STIG playbook
- /templates - Files used in template operations
- /vars/main.yml - variables referenced by photon task.  Reference these variables as needed for your environment and modify them by providing a vars file at the CLI.

## How to run

Run all controls on a single host. Prompts for user password, displays verbose output, and uses a vars file for inputs
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --extra-vars @vars-example.yml
```

Run all controls on a single host and only for a specific control PHTN-50-000001. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --tags PHTN-50-000001  
```

Run all controls on a single host and only for controls tagged 'photon' and also supplies variables at the command line. Prompts for user password and displays verbose output
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v --tags photon --extra-vars '{"var_syslog_server_name":"test.local","var_syslog_server_port":"514","var_ntp_servers":["time.vmware.com","time2.vmware.com"]}'
```

## Misc
- Steps requiring installs are enabled by default and should be disabled if internet access if not available.
- Enabling FIPS mode for the kernel is enabled by default. Update the run_fips_boot_enable variable to enable or disable it.
- For PAM configuration the playbook utilizes conf files for modules instead of adding properties directly to the `system-password`, `system-account`, and `system-auth` files.

## License
Copyright 2019-2021 VMware, Inc.  
SPDX-License-Identifier: Apache-2.0  
