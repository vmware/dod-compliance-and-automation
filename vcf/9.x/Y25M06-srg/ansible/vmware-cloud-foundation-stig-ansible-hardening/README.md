| [![Lint Ansible on Pushes](https://github-vcf.devops.broadcom.net/vcf/vmware-cloud-foundation-stig-ansible-hardening/actions/workflows/lint-ansible-on-push.yml/badge.svg?branch=main)](https://github-vcf.devops.broadcom.net/vcf/vmware-cloud-foundation-stig-ansible-hardening/actions/workflows/lint-ansible-on-push.yml) | Main | [![Lint Ansible on Pushes](https://github-vcf.devops.broadcom.net/vcf/vmware-cloud-foundation-stig-ansible-hardening/actions/workflows/lint-ansible-on-push.yml/badge.svg?branch=development)](https://github-vcf.devops.broadcom.net/vcf/vmware-cloud-foundation-stig-ansible-hardening/actions/workflows/lint-ansible-on-push.yml) | Development |
|:-|:-|:-|:-|
# vmware-cloud-foundation-stig-ansible-hardening
VMware Cloud Foundation STIG/SRG Ansible Playbook  
Updated: 2025-06-17
STIG Release: Y25M06  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

# :rotating_light: WARNING :rotating_light:
For the best experience, prior to using the STIG automation provided here please ensure the following has been completed:  
- Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the target environment.  
- Have an understanding of Ansible playbooks and concepts.
- Have a back out plan so that changes can be reverted if needed.
- Have read the README and understand the structure of the Ansible playbook provided here.

**Failure to do so can result in unintended behavior in the target environment.**  

## Overview
This is an Ansible playbook that can be used to perform automated remediation for STIG compliance of the VMware Cloud Foundation STIGs.  

All ansible roles needed to remediation STIG compliance for VCF have been consolidated into a single playbook starting in 9.0.0.0.  

## Supported Versions
- VCF 9.0.0.0  

## Support
- This playbook has not been tested for forward or backward compatibility beyond the version of VCF listed.  
- For more information on general STIG support, please see the [Support for Security Technical Implementation Guides](https://knowledge.broadcom.com/external/article?legacyId=94398) KB article.  

## Requirements
* General
  * [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/index.html) installed on a machine that can SSH to the target node(s).  Tested with Ansible `2.16.3`.
  * The Ansible requirements in the `requirements.yml` installed. Can be installed by running `ansible-galaxy roles install -r requirements.yml`
* Automation
  * Product Rules
    * API token obtained and populated in the vault `var_vault_automation_session_token` variable.
* HCX
  * Appliance Rules
    * SSH enabled
  * Product Rules
    * API token obtained and populated in the vault `var_vault_operations_hcx_session_token` variable.
* NSX
  * Product Rules
    * API token and session cookie obtained and populated in the vault `var_vault_nsx_manager_nsx_mgmt_mgr_1_session_token` and `var_vault_nsx_manager_nsx_mgmt_mgr_1_jsession_id` variables. Substitute inventory host name as appropriate.
* Operations
  * Appliance Rules
    * SSH enabled
  * Product Rules
    * API token obtained and populated in the vault `var_vault_operations_session_token` variable.
* Operations for Logs
  * Appliance Rules
    * SSH enabled
  * Product Rules
    * API token obtained and populated in the vault `var_vault_operations_logs_api_token` variable.
* Operations for Networks
  * Appliance Rules
    * SSH enabled
  * Product Rules
    * API token obtained and populated in the vault `var_vault_operations_networks_api_token` variable.
* Operations Fleet Management
  * Appliance Rules
    * SSH enabled
  * Product Rules
    * API token obtained and populated in the vault `var_vault_operations_fm_api_token` variable.
* SDDC Manager
  * Appliance Rules
    * SSH enabled
    * Temporarily allow root SSH by updating the /etc/ssh/sshd_config `PermitRootLogin`setting to `yes` and restart SSH by running `systemctl restart sshd`. This should be changed back to `no` after remediation.
  * Product Rules
    * API token obtained and populated in the vault `var_vault_sddcmgr_bearer_token` variable.
* vCenter
  * Appliance Rules
    * SSH enabled
    * The bash shell enabled on the vCenter appliance as the default shell for root. See the [Toggling the vCenter Server Appliance default shell](https://knowledge.broadcom.com/external/article/319670/toggling-the-vcenter-server-appliance-de.html) KB article for more details.
    * vCenter HA is NOT enabled.

### Required and Optional Variables
The following table of variables are either required or optionally needed depending on the deployment and if the default values are appropriate. Review the below variables carefully and ensure they are provided via `group_vars` or with `-e` as part of the `ansible-playbook` command.

|                    Variable Name                  |       Default Value       |                       Description                           |     Type    |    STIG IDs  |
|---------------------------------------------------|---------------------------|-------------------------------------------------------------|-------------|--------------|
|`automation_defaults_approved_feature_flags`       |`[]`                       |Array of approved feature flags that are approved for use.   |Array        |VCFA-9X-000375|
|`nsx_manager_defaults_syslog_servers`              |                           |List of approved syslog servers.                             |List of Dictionaries|VCFN-9X-000085|
|`nsx_manager_defaults_ntp_servers`                 |`[]`                       |Array of NTP servers.                                        |Array        |VCFN-9X-000111|
|`nsx_routing_defaults_t0_gateway_interfaces_with_multicast_enabled`|`[]`       |Array of T0 interface ids that should have multicast enabled.|Array        |VCFR-9X-000013|
|`nsx_routing_defaults_t0_gateways_with_dhcp_enabled`|`[]`                      |Array of T0 ids that should have dhcp enabled.               |Array        |VCFR-9X-000027|
|`nsx_routing_defaults_t0_gateways_with_multicast_enabled`|`[]`                 |Array of T0 ids that should have multicast enabled.          |Array        |VCFR-9X-000110|
|`nsx_routing_defaults_t1_gateways_with_dhcp_enabled`|`[]`                      |Array of T1 ids that should have dhcp enabled.               |Array        |VCFR-9X-000113|
|`nsx_routing_defaults_t1_gateways_with_multicast_enabled`|`[]`                 |Array of T1 ids that should have multicast enabled.          |Array        |VCFR-9X-000115|
|`ops_fm_defaults_time_servers`                     |`''`                       |Comma separated list of NTP servers with no spaces (i.e., '10.0.0.1,10.0.0.2').|String       |VCFA-9X-000371|
|`ops_hcx_defaults_time_servers`                    |`[]`                       |Array of NTP servers.                                        |Array        |VCFA-9X-000383|
|`ops_logs_defaults_ntp_servers`                    |`[]`                       |Array of NTP servers.                                        |Array        |VCFA-9X-000367|

## Ansible Concepts

### Playbook Structure
* `inventory_vcf.yml` -  Ansible inventory file for typical VCF deployments. This defines what VCF components will be targeted and how connections are made.  
* `playbook.yml` - Main playbook file that determines which roles run against systems in inventory groups. This is intended for appliance rule based remediation only via SSH.  
* `playbook_api.yml` - API role based playbook file that determines which roles run against systems in inventory groups. This is intended for product rule based remediation only via REST APIs.  
* `requirements.yml` - Used by the `ansible-galaxy` command to install required collections and roles needed by the playbook.  
* `vault_vcf.yml` - Ansible Vault file that defines credentials and other sensitive variables needed by the playbook.  
* `vars_xxx.yml` - Variables files used to supply environment specific variable values. 
* `/group_vars/xxx.yml` - Variables files that define variable values specific to inventory groups. These can only overwrite variables defined in role defaults.  
* `/host_vars/xxx.yml` - Variables files that define variable values specific to inventory hosts. These can only overwrite variables defined in role defaults and group_vars.  
* `/roles/<role name>/defaults/main.yml` - Control ID variables for each STIG rule that are can be used to enable or disable specific rules as well as configuration values that may be overwritten for the role. These can be overwritten by supplying a vars file at the command line or in group_vars and host_vars.  
* `/roles/<role name>/handlers/main.yaml` - Handlers are tasks that only run when notified. For example we can define a handler to restart a specific service and call the handler from any task that should restart that server when changes occur.  
* `/roles/<role name>/meta/main.yml` - Defines metadata for the role.  
* `/roles/<role name>/tasks/main.yml` - The primary task file for the role. This file usually references other task files in this directory.  
* `/roles/<role name>/templates/` - Template files used by the role.  
* `/roles/<role name>/vars/main.yml` - Variables used in tasks in the role are defined here for static configuration and system values. In this playbook these values are not intended to be overwritten or altered.  
* `/vars/vars_playbook.yml` - Variables defined here and intended to be used throughout the playbook and by multiple roles but are not intended to be altered.
* `/vars/vars_playbook_overrides.yml` - Variables defined here and intended to be used throughout the playbook and by multiple roles.

### Variable Precedence
Variables are used in Ansible to provide values to tasks being executed that are variable in nature. For example, values for site specific NTP servers or an API token to perform a task.

In order of least to greatest precedence.  For more information on variable precedence see: [Understanding variable precedence](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_variables.html#understanding-variable-precedence).

* `/roles/<role name>/defaults/main.yml`
* `/group_vars/xxx.yml`
* `/host_vars/xxx.yml`
* `/roles/<role name>/vars/main.yml`
* `/vars/vars_playbook.yml`
* `/vars/vars_playbook_overrides.yml`
* extra vars specified at the CLI with `-e` such as the vault file or a custom vars file.

__NOTE__: It is NOT supported to directly modify variables located in `/vars/vars_playbook.yml`, `/roles/<role name>/vars/main.yml`, `/roles/<role name>/defaults/main.yml`, or sections in group or host vars files inside blocks that state `DO NOT EDIT`. Follow the appropriate instructions to override variable values as needed for the target environment. 

### Variable Name Syntax
Variable names provided by this playbook are standardized based on where they originate to facilitate easy location.    

* `/roles/<role name>/defaults/main.yml` - Variables defined in a role in the defaults location will have the syntax `<rolename>_defaults_description`.
* `/roles/<role name>/vars/main.yml` - Variables defined in a role in the vars location will have the syntax `<rolename>_vars_description`.
* `vault_vcf.yml` - Variables originating from ansible vault will have the syntax `var_vault_<inventory_name>_description`.

### Variable use cases in this playbook and overriding values
Whether variables are used to control the execution of a specific STIG ID or to provide a value for a specific configuration as a general rule the default values provided are as called for in the STIG rules. The exception to this statement are values that are site specific such as for NTP or syslog servers where the value is empty by default and must be provided by the end user for the playbook to function properly.

#### Supported variable override locations and methods
It is supported to override role variables in the following ways:

* Adding target variables to `/group_vars/xxx.yml` files for a specific inventory group. For example, to set an NTP server for all NSX Managers update the `/group_vars/nsxmanager.yml` file.
* Adding target variables to `/host_vars/xxx.yml` files for a specific inventory host. For example, to set an NTP server for a single NSX Manager update the `/group_vars/nsx_mgmt_mgr_1.yml` file.
* Adding target variables to the `/vars/vars_playbook_overrides.yml` file to override variables for all roles. For example to disable the Photon rule that configures the DOD login banner for SSH on all inventory targets update `photon_5_defaults_run_phtn_50_000005_dod_banner: true` to `false`.
* By specifying a custom vars file during playbook execution with the `-e` argument.

#### Variable override use cases

* Disabling specific STIG rules.
  * Each STIG rule present in this playbook has a variable defined that controls the execution of that rule.
  * To override the default execution for a rule, locate the target role and review the `/defaults/main.yml` file for the available rule specific variables such as `photon_5_defaults_run_phtn_50_000044: true` and update the value in a supported location.
* Providing environment specific values.
  * Environment specific values exist for some rules such as to configure site specific NTP or syslog servers.
* Altering the STIG recommended value for a specific rule.
  * In rare cases a user may need to waiver to specific rule and/or alter the default value used by the playbook.
  * To override a configuration value, locate the target role and review the `/defaults/main.yml` file for the available configuration specific variables such as `photon_5_defaults_pam_pwquality_minlen: 15` and update the value in a supported location.

### Inventory
Ansible inventory is a list or groups of lists of the hosts or VCF appliances in this case that are targets of the Ansible playbook. The playbook is designed to target specific roles against specific inventory hosts.  

For example, from the `playbook.yml` file these are the roles that are ran against hosts in the vcenter inventory group:
```
- name: vmware-cloud-foundation-vcenter-stig-ansible-hardening
  hosts: vcenter
  roles:
    - role: photon_5
    - role: vcenter_envoy
    - role: vcenter_postgresql
    - role: vcenter_vami
```

The `inventory_vcf.yml` file serves as a starting point to building inventory for the target environment and represents what a single site deployment typically consists of. As each environment is different in regards to the number of workload domains, sites, clustered deployments, and components deployed an inventory file needs to be tailored to fit.

#### Inventory Customization
Depending on the size of the target VCF instance a single inventory file may be sufficient or if multiple sites/instances are deployed it may make sense to create an inventory file for each.

Inventory Guidelines
* Do not alter the group names since these are tied to specific roles in the playbook files.
* Host names in a group can be changed or hosts added to a group as needed.
  * If host specific variables are desired a corresponding file matching the hostname must exist in the `host_vars` folder.
  * Use only lowercase and underscores when adding hosts.
  * If adding hosts make sure the variable used for `ansible_password` has a corresponding entry in the vault file being used.
* Do not add new groups

Default inventory for vCenter servers in `inventory_vcf.yml`.
```
vcenter:
  hosts:
    vcenter_mgmt:
      ansible_host:
      ansible_user: root
      ansible_password: "{{ var_vault_vcenter_mgmt_root_password }}"
    vcenter_wld_1:
      ansible_host:
      ansible_user: root
      ansible_password: "{{ var_vault_vcenter_wld_1_root_password }}"
```

Customized example inventory for vCenter servers.
```
vcenter:
  hosts:
    vcenter_mgmt: 
      ansible_host: vcenter-mgmt.domain.local
      ansible_user: root
      ansible_password: "{{ var_vault_vcenter_mgmt_root_password }}"
    vcenter_wld_1:
      ansible_host: vcenter-wld-1.domain.local
      ansible_user: root
      ansible_password: "{{ var_vault_vcenter_wld_1_root_password }}"
    vcenter_wld_2:
      ansible_host: vcenter-wld-2.domain.local
      ansible_user: root
      ansible_password: "{{ var_vault_vcenter_wld_2_root_password }}"
```

### Tags
Ansible tags are primarily used in this playbook to associate STIG rules with specific tasks. These are useful in targeting specific tasks for a run.

Tags associated with STIG IDs for tasks example:
```
- name: PHTN-50-000005
  tags: [PHTN-50-000005, sshd]
  when: photon_5_defaults_run_phtn_50_000005 | bool
  block:
    - name: 'PHTN-50-000005 - Configure DoD Banner in {{ photon_5_vars_etc_issue_file }}.'
```

Tags are also present for each role so that a single role may be targeted for a run. These tags match the role name except with a -, for example:
```
- name: Include vCenter PostgreSQL tasks
  ansible.builtin.include_tasks:
    file: postgresql.yml
    apply:
      tags:
        - vcenter-postgresql
  tags:
    - vcenter-postgresql
```

### Using Ansible Vault
[Ansible vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html) provides a way to encrypt and manage sensitive data such as passwords.  

**!!It is critical that care is taken with the vault file and that it is not left unencrypted!!**

Before running the playbook, the `vault_vcf.yml` file or a copy or alternative vault file needs to be updated with the credentials needed for the playbook to run.

After updating the file it needs to be encrypted. For more information on how the vault is encrypted see: [Format of files encrypted with Ansible Vault](https://docs.ansible.com/ansible/latest/vault_guide/vault_using_encrypted_content.html#format-of-files-encrypted-with-ansible-vault)  

__NOTE__: All command examples below are assumed to be ran from the folder where the vault file resides.  

To encrypt the vault file, run the following command and supply a password for encryption:
```
ansible-vault encrypt vault_vcf.yml
```
To view an encrypted vault file, run the following command:
```
ansible-vault view vault_vcf.yml
```
To edit an encrypted vault file, run the following command:
```
ansible-vault edit vault_vcf.yml
```
To change the password on an encrypted vault file, run the following command:
```
ansible-vault rekey vault_vcf.yml
```
To decrypt the vault file, run the following command:
```
ansible-vault decrypt vault_vcf.yml
```

## Running the playbook
__NOTE__: All command examples below are assumed to be ran from the playbook folder and all required credentials and variables have already been populated.  

### File level backups
Each role if applicable contains a task that runs before any changes are made to backup any files the roles can potentially update.  

The backup files are saved to `"/tmp/ansible-backups-*{{ backup_timestamp }}/` which will be unique to each playbook run. Files saved under /tmp retain their original ownership and permissions.

When restoring files from these backups it is recommended to use the `-p` argument with the `cp` command to maintain the files permissions, owner, and timestamp. For example:  `cp -p source destination`  

If desired this backup task can be disabled by changing the variable `create_backups: true` to false in a supported vars override location.  

### General Ansible Playbook arguments
In the examples below some common arguments are used when running a playbook and are detailed here.

These arguments are commonly used in for various use cases when running this playbook.
* `-v` - Causes ansible to print more verbose output. Can be increased by adding more v's up to `-vvvvvv`.
* `-i` - Specifies an inventory target or inventory file to run against.
* `-l` - Limits the selection of hosts to run the playbook against. Should be used normally to not run against everything in inventory. For example only vCenter servers.
* `-e` - Set additional variables in key=value format for via a file if prepended with @. Using with a file is the most common.
* `--ask-vault-pass` - Prompt for vault password.
* `--tags` - Only run tasks with specific tags. This is most commonly used to target a specific STIG ID. For example: `--tags PHTN-50-000003,PHTN-50-000005`
* `--skip-tags` - Only run tasks that DO NOT match specific tags.

### vCenter Appliance Rules Remediation
Additional scenarios/arguments are presented here and can be applied to the rest of the component examples below. The examples are not exhaustive and targets and scope can be modified as needed.  
```
# Run all applicable roles on a single vCenter in inventory named vcenter_mgmt.
ansible-playbook playbook.yml -i inventory_vcf.yml -l vcenter_mgmt -v --ask-vault-pass -e @vault_vcf.yml

# Run subset of STIG rules by STIG ID on a single vCenter in inventory named vcenter_mgmt.
ansible-playbook playbook.yml -i inventory_vcf.yml -l vcenter_mgmt -v --ask-vault-pass -e @vault_vcf.yml --tags PHTN-50-000003,PHTN-50-000005

# Run a specific role by tag on a single vCenter in inventory named vcenter_mgmt.
ansible-playbook playbook.yml -i inventory_vcf.yml -l vcenter_mgmt -v --ask-vault-pass -e @vault_vcf.yml --tags photon

# Run all applicable roles on all vCenters in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l vcenter -v --ask-vault-pass -e @vault_vcf.yml
```

### NSX Remediation
```
# Run all applicable product-based roles on the first NSX Management domain manager in inventory.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l nsx_mgmt_mgr_1 -v --ask-vault-pass -e @vault_vcf.yml
```

### Automation Remediation
```
# Run all applicable product-based roles on the automation VIP target in inventory.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l automation_vip -v --ask-vault-pass -e @vault_vcf.yml
```

### Operations Remediation
```
# Run all applicable appliance-based roles on all Operations Master/Replica appliances in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable appliance-based roles on all Operations Data appliances in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_data -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable appliance-based roles on all Operations Cloud Proxy appliances in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_cloud_proxy -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable product-based roles on the Operations Master node in inventory.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_master -v --ask-vault-pass -e @vault_vcf.yml
```

### Operations for Logs Remediation
```
# Run all applicable appliance-based roles on all Operations for Logs appliances in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_logs -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable product-based roles on all Operations for Logs in inventory.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l operations_logs -v --ask-vault-pass -e @vault_vcf.yml
```

### Operations Fleet Management Remediation
```
# Run all applicable appliance-based roles on all Operations Fleet Management appliances in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_fm -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable product-based roles on all Operations Fleet Management targets in inventory.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l operations_fm -v --ask-vault-pass -e @vault_vcf.yml
```

### Operations For Networks Remediation
```
# Run all applicable appliance-based roles on all Operations for Networks Platform appliances in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_networks_platform -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable appliance-based roles on all Operations for Networks Proxy appliances in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_networks_proxy -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable product-based roles on the Operations for Networks ops_networks_platform_1 target in inventory.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_networks_platform_1 -v --ask-vault-pass -e @vault_vcf.yml
```

### SDDC Manager Remediation
```
# Run all applicable appliance-based roles on all SDDC Managers in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l sddcmgr -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable product-based roles on all SDDC Managers in inventory.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l sddcmgr -v --ask-vault-pass -e @vault_vcf.yml
```

### Operations HCX Remediation
```
# Run all applicable appliance-based roles on all Operations HCX Managers in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_hcx_mgr -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable appliance-based roles on all Operations HCX Connectors in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l operations_hcx_conn -v --ask-vault-pass -e @vault_vcf.yml

# Run all applicable product-based roles on Operations HCX Managers in inventory.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l operations_hcx_mgr -v --ask-vault-pass -e @vault_vcf.yml
```

## License
This project is available under the [Apache License, Version 2.0](LICENSE).