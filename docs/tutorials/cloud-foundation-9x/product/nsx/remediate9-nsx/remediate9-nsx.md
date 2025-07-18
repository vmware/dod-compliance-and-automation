# Remediate NSX 9.0.0.0

## Overview
This tutorial covers remediating NSX in VCF deployments.  

> **Important** For the best experience, prior to using the STIG automation provided here please ensure you:  

> - Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
> - Have an understanding of Ansible playbooks and concepts.
> - Have a back out plan so the changes can be rolled back if necessary.
> - Have read the [Ansible Overview](/docs/tutorials/cloud-foundation-9.x/ansible-playbook_overview/) and understand the structure of the Ansible playbook provided here.

> **Failure to do so can result in unintended behavior in the environment.**  

The example commands below are specific to the product version and the supported STIG content for the version being run.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.14.12
* A VCF 9.0.0.0 or newer environment.
* Ansible Inventory, Vault, and any environment specific variables have been updated.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work (for the PowerCLI portions only) but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* Ansible has been installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.

## Remediating NSX
To remediate NSX an Ansible playbook has been provided that will target an NSX Manager or Managers via the NSX API and configure any non-compliant controls.  

### Generate an API Session Token
This profile uses Session-Based authentication to authenticate with NSX for auditing. A session token can be retrieved through the `/api/session/create` API call. 

A token can be generated via curl or other REST client. A curl example is shown below.

For more information see the [NSX API Documentation](https://developer.vmware.com/apis/1733/).

> **Note** If the user is a remote user, append "@domain" to the username, for example, "joe@example.com". The domain must match a domain for a configured identity source or a configured LDAP identity source.  

Curl example:

```
# Replace myuser, mypassword, and update the url
curl -k -i -X POST -d 'j_username=myuser&j_password=mypassword' https://nsxmgr.rainpole.local/api/session/create

# Example response
HTTP/1.1 200
Set-Cookie: JSESSIONID=0FB1F72478DDE578AB7E3473F54BCF50; Path=/; Secure; HttpOnly
X-XSRF-TOKEN: ae5ee920-bca1-4ba3-ac1f-385e76f2c66a
```

### Update Ansible Inventory and Vault with the target NSX details
In the Ansible inventory file and vault ensure the target NSX Manager details are correct.

```
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the NSX Manager inventory group and update the existing hosts and add additional hosts as needed.
nsxmanager:
  hosts:
    nsx_mgmt_mgr_1:
      ansible_host: nsxmgr.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_nsx_manager_nsx_mgmt_mgr_1_root_password }}"

# Update the credentials for the target NSX Manager in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the NSX Manager credential variables and update and save (:wq)
# The root password for NSX is not needed at this time.
var_vault_nsx_manager_nsx_mgmt_mgr_1_jsession_id:
var_vault_nsx_manager_nsx_mgmt_mgr_1_session_token:

# Update NSX environment specific values in the nsxmanager.yml group_vars file or via an alternatively provided vars files that is specified at the command line
vi group_vars/nsxmanager.yml

## Enter an array of NTP servers to configure for NSX Manager
nsx_manager_defaults_ntp_servers:
  - 'time-a-g.nist.gov'
  - 'time-b-g.nist.gov'

## Enter an array of syslog servers to configure for NSX Manager
### Server is the IP or FQDN of the syslog server
### Port defaults to 514 for TCP, TLS, UDP protocols or 9000 for LI, LI-TLS protocols
### Protocol is one of TCP, TLS, UDP, LI, LI-TLS
### Level is one of EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG
nsx_manager_defaults_syslog_servers:
  - server: 'opslogs.rainpole.local'
    port: 514
    protocol: 'TCP'
    level: 'INFO'
```

### Running the playbook
To remediate all NSX rules, follow the example below:

```# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target only the nsx_mgmt_mgr_1 inventory host.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l nsx_mgmt_mgr_1 -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single NSX Manager in inventory named nsx_mgmt_mgr_1.
ansible-playbook playbook.yml -i inventory_vcf.yml -l nsx_mgmt_mgr_1 -v --ask-vault-pass -e @vault_vcf.yml --tags VCFN-9X-000007

# Run a specific role by tag on a single NSX Manager in inventory named nsx_mgmt_mgr_1.
ansible-playbook playbook.yml -i inventory_vcf.yml -l nsx_mgmt_mgr_1 -v --ask-vault-pass -e @vault_vcf.yml --tags nsx-manager

# Run all applicable roles on all NSX Managers in inventory.
ansible-playbook playbook.yml -i inventory_vcf.yml -l nsxmanager -v --ask-vault-pass -e @vault_vcf.yml

# Output example
TASK [nsx_manager : VCFN-9X-000012 - Update authentication policy] ************************************************************************************************************************************************************
changed: [nsx_mgmt_mgr_1] => {"changed": true, "connection": "close", "content_length": "602", "content_security_policy": "frame-src 'self' https://*.vmware-aws.com/ https://*.vmware.com https://*.broadcom.com blob:; frame-ancestors 'self' https://*.vmware-aws.com/ https://*.vmware.com https://*.broadcom.com", "content_type": "application/json", "cookies": {}, "cookies_string": "", "date": "Wed, 14 May 2025 21:31:48 GMT", "elapsed": 11, "json": {"_retry_prompt": 3, "_schema": "AuthenticationPolicyProperties", "_self": {"href": "/node/aaa/auth-policy", "rel": "self"}, "api_failed_auth_lockout_period": 900, "api_failed_auth_reset_period": 900, "api_max_auth_failures": 3, "cli_failed_auth_lockout_period": 900, "cli_max_auth_failures": 3, "digits": -1, "hash_algorithm": "sha512", "lower_chars": -1, "max_repeats": 0, "max_sequence": 0, "maximum_password_length": 128, "minimum_password_length": 12, "minimum_unique_chars": 0, "password_remembrance": 0, "special_chars": -1, "upper_chars": -1}, "msg": "OK (602 bytes)", "redirected": false, "server": "envoy", "status": 202, "strict_transport_security": "max-age=31536000; includeSubDomains", "url": "https://nsxmgr.rainpole.local/api/v1/node/aaa/auth-policy", "vmw_task_id": "71141642-fd95-8e7e-1c50-e167d8d6ffd8_70793f91-74fc-4ec4-bee2-2cb0d59bb136", "x_content_type_options": "nosniff", "x_envoy_upstream_service_time": "10986", "x_frame_options": "SAMEORIGIN", "x_xss_protection": "1;mode=block"}

TASK [nsx_manager : VCFN-9X-000012 - Pause to give the service restart a chance to happen when changes are made to auth policy] ***********************************************************************************************
Pausing for 15 seconds
ok: [nsx_mgmt_mgr_1] => {"changed": false, "delta": 15, "echo": true, "rc": 0, "start": "2025-05-14 21:31:48.240723", "stderr": "", "stdout": "Paused for 15.0 seconds", "stop": "2025-05-14 21:32:03.241036", "user_input": ""}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
nsx_mgmt_mgr_1             : ok=80   changed=9    unreachable=0    failed=0    skipped=65   rescued=0    ignored=0
```

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFN-9X-000010`     |The VMware Cloud Foundation NSX Manager must be configured to assign appropriate user roles or access levels to authenticated users.     |
| `VCFN-9X-000091`     |The VMware Cloud Foundation NSX Manager must be configured to conduct backups on an organizationally defined schedule.                   |
| `VCFR-9X-000016`     |The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to have all inactive interfaces removed.                               |
| `VCFR-9X-000029`     |The VMware Cloud Foundation NSX Tier-0 Gateway router must be configured to use encryption for OSPF routing protocol authentication.     |
| `VCFR-9X-000055`     |The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to use a unique password for each autonomous system (AS) with which it peers.|
| `VCFR-9X-000091`     |The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to use its loopback address as the source address for iBGP peering sessions.|
| `VCFR-9X-000111`     |The VMware Cloud Foundation NSX Tier-0 Gateway router must be configured to use encryption for BGP routing protocol authentication.      |
| `VCFR-9X-000112`     |The VMware Cloud Foundation NSX Tier-1 Gateway must be configured to have all inactive interfaces removed.                               |

## Functional Testing
Perform any needed functional testing to ensure the functionality and operation of the environment remain intact.

## Rerun auditing after remediation
To audit NSX post-remediation rerun the auditing steps [here](/docs/tutorials/cloud-foundation-9.x/product/nsx/audit9-nsx/).
