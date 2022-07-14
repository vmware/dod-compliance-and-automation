# vmware-cloud-director-10.4-stig-ansible-hardening
VMware Cloud Director 10.4 STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 1: July 14, 2022    
STIG Type: STIG Readiness Guide  

## Overview
This is a hardening playbook that utilizes Ansible to perform automated remediation for STIG compliance of the VMware Cloud Director 10.4 STIG Readiness Guide.  

## Requirements
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/index.html) installed on a machine that can SSH to the target node(s).  Tested with Ansible 2.12.4.
- SSH access to target server if not running it locally
- Sudo access to target server if needed

## Playbook Structure

- playbook.yml - Main playbook to run
- requirements.yml - Requirements file for installing dependencies or other roles included in this playbook
- /roles/<role name>/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/<role name>/handlers/main.yaml - handlers referenced in the tasks
- /roles/<role name>/tasks/main.yml - Default role playbook
- /roles/<role name>/templates - Any template files used in the role
- /roles/<role name>/vars/main.yml - variables referenced by tasks.  Update these variables as needed for your environment.

## How to run

Run all controls on a single host. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v -b
```
Run all controls on a single host and only for a specific control DKER-CE-000001. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v -b --tags DKER-CE-000001  
```
Run all controls on a single host and only for a specific group of controls for containerd. Prompts for user password and displays verbose output  
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v -b --tags containerd  
```
Run all controls on a single host and only for controls tagged 'log_opts' and also supplies variables at the command line. Prompts for user password and displays verbose output
```
ansible-playbook -i 'IP or FQDN', -u 'username' playbook.yml -k -v -b --tags log_opts --extra-vars '{"log_opts_max_size": "100m", "log_opts_max_file": "2"}'
```

## Misc
- If vars need to be updated we recommend either creating a vars file to specify at the command line or adding them to the main playbook.yml or your own playbook.yml so that it is easy to track what is being altered from the original state.  
- Requirements can be installed by running
```
ansible-galaxy roles install -r requirements.yml
```

## Control Coverage
The following table lists the controls that must be manually checked and are not covered by this playbook.

|  STIG ID  |        Title       |
|:---------:|------------------|
| PSQL-00-000005 | PostgreSQL must enable pgaudit to provide audit record generation capabilities. | 
| PSQL-00-000028 | Database software, including PostgreSQL configuration files, must be stored in dedicated directories separate from the host OS and other applications. | 
| PSQL-00-000029 | PostgreSQL objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers) must be owned by principals authorized for ownership. | 
| PSQL-00-000030 | The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, etc.) must be restricted to authorized users. | 
| PSQL-00-000032 | PostgreSQL must not load unused database components, software, and database objects. | 
| PSQL-00-000044 | PostgreSQL must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations. | 
| PSQL-00-000124 | PostgreSQL must be a version supported by the vendor. | 
