# vmware-nsx-4.x-stig-ansible-hardening
VMware NSX 4.x STIG Readiness Guide Ansible Playbook  
Version: Version 1 Release 1: March 7, 2023  
STIG Type: STIG Readiness Guide  
Maintainers: VMware  

## Overview
This is a hardening playbook that utilizes Ansible to perform automated remediation for STIG compliance of the VMware NSX 4.x STIG Readiness Guide.  

## !!Important!!
- Please read through the README carefully and familiarize yourself with the playbook and ansible before running this playbook
- As always please ensure you have a backout plan if needed you can roll back the changes
- This playbook has not been tested for forward or backward compability beyond the version of NSX listed under requirements.
- Some NSX-T STIG controls can be very impactful to your environment if care is not taken during implementation especially in a brownfield scenario. For example, changing the default DFW rule to deny traffic without first creating rules to allow authorized traffic. 

## Requirements
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/index.html) installed on a machine that can SSH to the target node(s).  Tested with Ansible 2.14.4.
- Install [JMESPath](https://pypi.org/project/jmespath/) for community.general.json_query collection.
- an API token is needed and must be provided at the CLI or vars file
- The manager IP or FQDN must be provided at the CLI or vars file
- This playbook does not include remediation for the SDN Controller controls
- An account with sufficient privileges to configure NSX  

## Playbook Structure

- playbook.yml - Main playbook to run
- requirements.yml - Requirements file for installing dependencies or other roles included in this playbook
- vars-nsx-4x-example.yml - Example vars file to profile variable values to the playbook for use during execution
- /roles/<role name>/defaults/main.yml - Default variables used to turn controls on/off in the playbook.  Set these to true/false
- /roles/<role name>/handlers/main.yaml - handlers referenced in the tasks
- /roles/<role name>/tasks/main.yml - Default role task file
- /roles/<role name>/templates - Any template files used in the role
- /roles/<role name>/vars/main.yml - variables referenced by tasks.  Update these variables as needed for your environment.

## Generate API Session Token
This playbook uses Session-Based authentication to authenticate with NSX for remediation. A session token and cookie must be generated and provided an input for the profile. This can be generated in various ways via curl, tools like Postman, etc. For more information see the [NSX API Documentation](https://developer.vmware.com/apis/1583/nsx-t).

**Note:** If the user is a remote user, append "@domain" to the username, for example, "joe@example.com". The domain must match a domain for a configured VIDM identity source or a configured LDAP identity source.  

## Update vars file
In order to run the playbook, environment specific values need to be provided. An example vars file `vars-nsx-4x-example.yml` is provided and values need to be updated for the `var_nsx_manager`, `var_jsession_id`, `var_session_token`, `var_ntp_server1`, `var_ntp_server2` variables at a minimum.  

## How to run
Run all controls for NSX-T and specify a vars file.
```
ansible-playbook playbook.yml -v --extra-vars @vars-nsx-4x-example.yml
```
Run controls for one role (manager in this example) by specifying a tag.  
```
ansible-playbook playbook.yml -v --extra-vars @vars-nsx-4x-example.yml --tags manager
```
Run a specific control by specifying a tag.  
```
ansible-playbook playbook.yml -v --extra-vars @vars-nsx-4x-example.yml --tags NDFW-4X-000004
```

**Note:** All commands above are ran from the playbooks root directory. If running from a different location adjust the paths accordingly.  le-playbook playbook.yml -v --extra-vars @vars-nsx-4x-example.yml --tags NMGR-4X-000097

## Misc
- If vars need to be updated we recommend either creating a vars file to specify at the command line or adding them to the main playbook.yml or your own playbook.yml so that it is easy to track what is being altered from the original state.  
