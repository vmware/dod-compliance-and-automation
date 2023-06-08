---
title: "Remediate Cloud Foundation 5.x"
weight: 4
description: >
  Remediating VCF 5.x for STIG Compliance
---
## Overview
Remediating VCF for STIG compliance involves running an Ansible playbook on the SDDC Manager appliance.  

Remediating other components of a VCF deployment such as [vSphere](/docs/tutorials/vsphere) and [NSX](/docs/tutorials/NSX) is documented in those sections on this site. 

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vmware-cloud-foundation-sddcmgr-5x-stig-ansible-hardening](https://github.com/vmware/dod-compliance-and-automation/tree/master/vcf/5.x/ansible/vmware-cloud-foundation-sddcmgr-5x-stig-ansible-hardening) playbook downloaded.
* The [vmware-photon-3.0-stig-ansible-hardening](https://github.com/vmware/dod-compliance-and-automation/tree/master/photon/3.0/inspec/vmware-photon-3.0-stig-ansible-hardening) playbook downloaded.
* Ansible 2.14.6
* A VCF 5.x environment. 5.0 was used in these examples.
* An account with access to VCF.

## Remediating SDDC Manager appliance controls
To remediate vCenter we have provided an [Ansible playbook](https://github.com/vmware/dod-compliance-and-automation/tree/master/vcf/5.x/ansible/vmware-cloud-foundation-sddcmgr-5x-stig-ansible-hardening) that will target a single SDDC Manager appliance over SSH and configure any non-compliant controls.  

Since Ansible can only be ran from Linux based systems, the examples below are being ran on an Ubuntu 22.04 WSL2 instance on Windows 11 for reference.  

### Backups
Before running it is highly advised to have a backup of the SDDC Manager and/or snapshot available if a rollback is required. Also the playbook will backup files configured before updates and place them under the /tmp directory in a folder directly on the SDDC Manager appliance. 

### Update the SSH config to allow remediation
By default the SDDC Manager appliance does not allow root SSH and the `vcf` does not have the required privileges to run the playbook so root SSH must be temporarily enabled to complate the scan. These steps can be reversed once the audit is complete.  

```bash
# Allow root SSH into SDDC manager
ssh vcf@sddc-manager.vsphere.local
su -
vi /etc/ssh/sshd_config
# Update PermitRootLogin from no to yes and save
systemctl restart sshd
```

### Ansible dependencies
The playbook is written to use the separate Photon 3.0 playbook we have avaiable and must be installed as a role prior to running.  

Also there are two ansible collections that must be installed if on a version of Ansible newer than 2.9.  

```bash
# Installing playbook requirements from the requirements.yml file provided.
ansible-galaxy roles install -r requirements.yml
```

### Generate bearer token for SDDC Manager
The SDDC Manager Ansible playbook connects to the API via a bearer token to update product controls while the appliance controls are configured via SSH.  

This is a curl example. This can also be done via other methods such as Postman. 
```bash
# Ran from a Linux machine.
curl -k 'https://sddc-manager.vrack.vsphere.local/v1/tokens' -i -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -d '{
  "username" : "administrator@vsphere.local",
  "password" : "replaceme"
}'
```

A token can also be generated UI by going to the Developer Center >> API Explorer >> Tokens.  
![alt text](/images/vcf5_generate_token.png)

Retrieve token by copying the value in the `accessToken` field.  
![alt text](/images/vcf5_view_token.png)

### Update vars file
In order to run the playbook, environment specific values need to be provided. An example vars file is provided and values need to be updated for the `var_sddc_manager`, `var_bearer_token`, `var_time_servers` variables.  

```yaml
# General
run_create_backups: true

# Photon OS
var_syslog_authpriv_log: '/var/log/audit/auth.log'
## Don't update banner with DoD banner
run_sshd_banner_issue: true
# NTP is covered in the Application controls
run_set_ntp_server: false

# Application
# Enter SDDC Manager FQDN or IP for API Calls
var_sddc_manager: 'sddc-manager.vrack.vsphere.local'
# Enter generated bearer token here
var_bearer_token: 'UNDT1VOVF9XUklURSIsIk5FVFdPUktfUE9PTF9SRUFEIiwiQ0FfV1JJVEUiLCJDTFVTVEVSX1JFQUQiLCJWQVNBX1BST1ZJREVSX1dSSVRFIiwiRE5TX1dSSVRFIiwiU1lTVEVNX1dSSVRFIiwiVlJTTENNX1dSSVRFIiwiRE5TX1JFQUQiLCJTRVJWSUNFX0FDQ09VTlRfUkVBRCIsIlNERENfRkVERVJBVElPTl9SRUFEIiwiE9NQUlOX1JFQUQiLCJWUlNMQ01fUkVBRCIsIlVQR1JBREVfV1JJVEUiXSwicm9sZSI6WyJBRE1JTiJdfQ'
# Enter an array of 1 to 2 NTP servers
var_time_servers:
  - 'time-a-g.nist.gov'
  - 'time-b-g.nist.gov'
# Between 30 and 90
var_password_rotate_days: 90
```

### Running the playbook
To run all of the SDDC Manager controls, follow the example below.
```bash
# The -k parameter will prompt for password and we are using extra-vars to specify a variable file for the playbook to use. Command assume it is being ran from the playbook folder.
> ansible-playbook -i 10.0.0.4, -u 'root' playbook.yml -k -v --extra-vars @vars-sddcmgr-example.yml

# Output example
TASK [application : CFAP-5X-000127 - Set credential rotate policy] ************************************************************************************************************************************************************************
changed: [10.0.0.4] => {"cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": true, "connection": "close", "content_type": "application/json", "cookies": {}, "cookies_string": "", "date": "Thu, 01 Jun 2023 18:19:36 GMT", "elapsed": 0, "expires": "0", "json": {"id": "f0f9e481-9555-46ea-bbc0-76d144323fe6", "status": "IN_PROGRESS"}, "location": "https://sddc-manager.vrack.vsphere.local/v1/tasks/f0f9e481-9555-46ea-bbc0-76d144323fe6", "msg": "OK (unknown bytes)", "pragma": "no-cache", "redirected": false, "server": "nginx", "status": 202, "transfer_encoding": "chunked", "url": "https://sddc-manager.vrack.vsphere.local/v1/credentials", "x_content_type_options": "nosniff", "x_frame_options": "DENY", "x_xss_protection": "1; mode=block"}

TASK [application : CFAP-5X-000127 - Wait for task to complete] ***************************************************************************************************************************************************************************
ok: [10.0.0.4] => {"attempts": 1, "cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": false, "connection": "close", "content_type": "application/json;charset=UTF-8", "cookies": {}, "cookies_string": "", "date": "Thu, 01 Jun 2023 18:19:37 GMT", "elapsed": 0, "expires": "0", "json": {"creationTimestamp": "2023-06-01T18:19:36.784Z", "errors": [], "id": "f0f9e481-9555-46ea-bbc0-76d144323fe6", "isCancellable": false, "name": "Credentials update auto rotate policy operation", "resolutionStatus": "UNRESOLVED", "status": "SUCCESSFUL", "subTasks": [{"completionTimestamp": "2023-06-01T18:19:36.784Z", "creationTimestamp": "2023-06-01T18:19:36.784Z", "description": "Prevalidation of password update auto rotate policy request", "name": "Password update auto rotate policy prevalidation", "status": "SUCCESSFUL"}], "type": "PASSWORD_AUTO_ROTATE_POLICY_UPDATE"}, "msg": "OK (unknown bytes)", "pragma": "no-cache", "redirected": false, "referrer_policy": "no-referrer", "server": "nginx", "status": 200, "strict_transport_security": "max-age=15768000", "transfer_encoding": "chunked", "url": "https://sddc-manager.vrack.vsphere.local/v1/tasks/f0f9e481-9555-46ea-bbc0-76d144323fe6", "x_content_type_options": "nosniff, nosniff", "x_frame_options": "DENY, SAMEORIGIN", "x_xss_protection": "1; mode=block"}

TASK [application : CFAP-5X-000128 - The SDDC Manager must use an account dedicated for downloading updates and patches.] *****************************************************************************************************************
ok: [10.0.0.4] => {
    "msg": "CFAP-5X-000128 - This control must be manually remediated."
}

TASK [application : CFAP-5X-000129 - Get current basic auth status] ***********************************************************************************************************************************************************************
ok: [10.0.0.4] => {"cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": false, "connection": "close", "content_type": "application/json;charset=UTF-8", "cookies": {}, "cookies_string": "", "date": "Thu, 01 Jun 2023 18:19:39 GMT", "elapsed": 0, "expires": "0", "json": {"basicAuthDetails": {"status": "ENABLED", "username": "admin"}, "domain": {"id": "529797b0-1b5c-4f90-a956-44b2398edba9"}, "fqdn": "sddc-manager.vrack.vsphere.local", "id": "dd56c751-49b5-4a69-957c-009a7ea79147", "ipAddress": "10.0.0.4", "version": "5.0.0.0-21822418"}, "msg": "OK (unknown bytes)", "pragma": "no-cache", "redirected": false, "referrer_policy": "no-referrer", "server": "nginx", "status": 200, "strict_transport_security": "max-age=15768000", "transfer_encoding": "chunked", "url": "https://sddc-manager.vrack.vsphere.local/v1/sddc-manager", "x_content_type_options": "nosniff, nosniff", "x_frame_options": "DENY, SAMEORIGIN", "x_xss_protection": "1; mode=block"}

TASK [application : CFAP-5X-000129 - Disable Basic Auth] **********************************************************************************************************************************************************************************
changed: [10.0.0.4] => {"cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": true, "connection": "close", "content_length": "0", "cookies": {}, "cookies_string": "", "date": "Thu, 01 Jun 2023 18:19:40 GMT", "elapsed": 0, "expires": "0", "msg": "OK (0 bytes)", "pragma": "no-cache", "redirected": false, "referrer_policy": "no-referrer", "server": "nginx", "status": 200, "strict_transport_security": "max-age=15768000", "url": "https://sddc-manager.vrack.vsphere.local/v1/sddc-manager", "x_content_type_options": "nosniff, nosniff", "x_frame_options": "DENY, SAMEORIGIN", "x_xss_protection": "1; mode=block"}
```

A more conservative and preferred approach is to target any non-compliant controls or run each component separately allowed you to perform any functional testing in between.
```bash
# Providing the tag "application" will instruct the playbook to only run the application role. This tag can be seen in each roles task/main.yml file.
> ansible-playbook -i 10.0.0.4, -u 'root' playbook.yml -k -v --extra-vars @vars-sddcmgr-example.yml --tags application

# Providing the tag "CFAP-5X-000002" will instruct the playbook to only run task tagged with the STIG ID of CFAP-5X-000002.
> ansible-playbook -i 10.0.0.4, -u 'root' playbook.yml -k -v --extra-vars @vars-sddcmgr-example.yml --tags CFAP-5X-000002
```