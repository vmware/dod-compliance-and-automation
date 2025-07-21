# Remediate VCF 9.x

## Overview
This tutorial covers remediating the VCF Application STIG in VCF deployments which includes product rules for the following components:

- Automation
- Identity Broker
- Operations
- Operations Fleet Management
- Operations for Logs
- Operations for Networks
- Operations HCX
- SDDC Manager
- vCenter

Auditing these components can occur individually or together. vCenter remediation is accomplished via a PowerCLI script while the remaining components are remediated with Ansible.  

> **Important** For the best experience, prior to using the STIG automation provided here please ensure you:  

> - Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
> - Have an understanding of Ansible playbooks and concepts, PowerShell, and PowerCLI.
> - Have a back out plan so the changes can be rolled back if necessary.
> - Have read the [Ansible Overview](/docs/tutorials/cloud-foundation-9x/ansible-playbook-overview.md) and understand the structure of the Ansible playbook provided here.
> - Have read the [PowerCLI Overview](/docs/automation-tools/powercli.md).

> **Failure to do so can result in unintended behavior in the environment.**  

The example commands below are specific to the product version and the supported STIG content for the version being run.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Ansible 2.14.12
* Ansible Inventory, Vault, and any environment specific variables are updated.
* A VCF 9.0.0.0+ environment
* PowerShell Core 7.4.7/PowerShell 5.1
* VCF PowerCLI 9.0.0.0+
* VCF STIG Helpers PowerShell module 1.0.1+
* Ansible has been installed and all playbook dependencies resolved as provided in the `requirements.yml` file in each playbook. Install with `ansible-galaxy role install -r requirements.yml`.

#### VCF STIG Helpers PowerShell Module
The VCF STIG Helpers PowerShell module provides additional supporting functions to the scripts provided here and for the vSphere InSpec profiles.  

The functions provided are: `Set-vCenterCredentials` `Get-vCenterCredentials` `Set-PowerCLICredential` `Get-PowerCLICredentialUsername` `Get-PowerCLICredentialPassword` `Write-Message` `Write-Header` `Test-PowerCLI` `Test-vCenter` `Test-ESX`

### Assumptions
* Commands are being run from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.

## Remediating vCenter
Prior to running any scripts it is recommended to familiarize yourself with the scripts and the required parameters as well as test them out in a non-production environment.  

### Included Scripts

- `VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1` - Global variables used throughout all scripts.  
- `VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Variables.ps1` - Variables specific to vCenter remediation. Environment specific, rule enablement/disablement, expected STIG values, default values for revert workflow.  
- `VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation.ps1` - Remediation script for vCenter.  

### Common Parameters
The follow parameters are available in all remediation scripts.  

|   Parameter Name  |       Default Value       |                                     Description                                |          Type         |
|-------------------|---------------------------|--------------------------------------------------------------------------------|-----------------------|
| `vccred`          |`None`                     |PowerShell credential object for use in connecting to the target vCenter server.|`PowerShell Credential`|
| `NoSafetyChecks`  |`$false`                   |Skip safety checks to verify PowerCLI, vCenter, and ESX versions before running script.|`Boolean`       |
| `RevertToDefault` |`$false`                   |When specified the script will revert all settings back to the known default 'Out of the Box' values.|`Boolean`       |
| `GlobalVarsFile`  |`VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1`|Global Variables file name. Must be in the same directory as the script.|`String`       |
| `RemediationVarsFile`|`VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Variables.ps1`|Remediation Variables file name. Must be in the same directory as the script.   |`String`       |

### Update environment specific variables
Update the `VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1` and `VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Variables.ps1` files with the target environment values for remediation. The file provided can be used or a copy can be made and updated.  

> **Note** Update paths as needed for the environment.  

```bash
# Navigate to the PowerCLI hardening folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/

# Update the report path if needed and provide the vCenter server name.
vi VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1

# In this example a single ESX host named esx1.rainpole.local will be targeted
$ReportPath = "/tmp/reports"
$vcenter = "vcenter.rainpole.local"

# Update environment specific ESX variables
vi VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Variables.ps1

# Update any environment specific variables as needed. To disable/enable rules update the $rulesenabled section.
envstigsettings = [ordered]@{
  ssoDomain                       = "vsphere.local" # Update this if a different SSO domain name was used when deploying vCenter. This is vsphere.local by default.
  ntpServers                      = @("time-a-g.nist.gov","time-b-g.nist.gov") # VCFA-9X-000153 Enter array of NTP servers
  netflowCollectorIp              = "" # VCFA-9X-000326 Enter the authorized NetFlow collector IP if used.
  netflowDisableonallPortGroups   = $true # VCFA-9X-000326 If Netflow is not used disable it on all port groups
  allowedBashAdminUsers           = @() # VCFA-9X-000333 List of allowed users in the SystemConfiguration.BashShellAdministrators SSO group. Administrator and the default service accounts do not need to be listed here.
  allowedBashAdminGroups          = @() # VCFA-9X-000333 List of allowed groups in the SystemConfiguration.BashShellAdministrators SSO group. Empty by default.
  allowedPortMirroringSessions    = @() # VCFA-9X-000340 Enter an array of port mirroring sessions by name that are allowed.
}
```

### Run the remediation script

> **Caution** If remediation is needed for rule VCFA-9X-000004 to change the TLS profile of vCenter a service restart will take place and a loss of connectivity to vCenter may be seen for a few minutes.  

```powershell
# Launch PowerShell
pwsh

# Create a PowerShell credential. The provided user must have administrative permissions to the target vCenter and vCenter SSO.
$vccred = Get-Credential

User: administrator@vsphere.local
Password for user administrator@vsphere.local: ********************

# Run the remediation script against the target ESX hosts
./VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation.ps1 -vccred $vccred

# Snippet from the output of running the script.
[2025-05-19 22:10:40] [INFO] Importing Global Variables from: /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1
[2025-05-19 22:10:40] [INFO] Importing Remediation Variables from: /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Variables.ps1
[2025-05-19 22:10:40] [INFO] Starting Powershell Transcript at /tmp/reports/VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Transcript_5-19-2025_22-10-40.txt
Transcript started, output file is /tmp/reports/VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Transcript_5-19-2025_22-10-40.txt
[2025-05-19 22:10:40] [INFO] VMware vSphere vCenter STIG Remediation - STIG Readiness Guide Version 1 Release 1
[2025-05-19 22:10:40] [EULA] Use of this tool constitutes acceptance of the license and terms of use found at:
[2025-05-19 22:10:40] [EULA] https://github.com/vmware/dod-compliance-and-automation
[2025-05-19 22:10:40] [INFO] Remediation of vcenter.rainpole.local started at 2025-05-19 22:10:40 from  by root
[2025-05-19 22:10:40] [SAFETY] This script requires PowerCLI 9.0.0 or newer. Current version is 9.0.0.24720632.
[2025-05-19 22:10:40] [INFO] Connecting to vCenter: vcenter.rainpole.local
[2025-05-19 22:10:47] [INFO] Connecting to vCenter SSO: vcenter.rainpole.local
[2025-05-19 22:10:48] [SAFETY] This script supports vCenter version 9.0.0 to 9.0.0. Current version is 9.0.0.
[2025-05-19 22:10:48] [INFO] Gathering info on target vCenter: vcenter.rainpole.local
[2025-05-19 22:10:49] [INFO] Remediating STIG ID: VCFA-9X-000004 with Title: The VMware Cloud Foundation vCenter Server must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.
[2025-05-19 22:10:50] [CHANGED] SSO lockout policy updated to MaxFailedAttempts: 5 and FailedAttemptIntervalSec: 180 on vCenter: vcenter.rainpole.local.
[2025-05-19 22:11:06] [INFO] Configuration Summary:
[2025-05-19 22:11:06] [INFO] {
  "vcenter": "vcenter.rainpole.local",
  "hostname": "",
  "cluster": "cluster1",
  "vmhosts": null,
  "reportpath": "/tmp/reports",
  "ok": 46,
  "changed": 21,
  "skipped": 16,
  "failed": 1

# A results file and PowerShell transcript is provided in the report path specified.
Directory: /tmp/reports

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---            5/14/2025  14:46 PM           6578 VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Results_5-14-2025_14-46-40.json
-a---            5/14/2025  14:46 PM          84552 VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Transcript_5-14-2025_14-46-40.txt
```

## Manually remediate rules
The following rules require manual remediation if not compliant and are not automated by the provided scripts.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFA-9X-000018`     |The VMware Cloud Foundation vCenter Server must display the Standard Mandatory DOD Notice and Consent Banner before logon.               |
| `VCFA-9X-000051`     |VMware Cloud Foundation vCenter Server client plugins must be verified.                                                                  |
| `VCFA-9X-000082`     |The VMware Cloud Foundation vCenter Server must terminate sessions after 15 minutes of inactivity.                                       |
| `VCFA-9X-000090`     |VMware Cloud Foundation vCenter Server assigned roles and permissions must be verified.                                                  |
| `VCFA-9X-000257`     |The VMware Cloud Foundation vCenter Server must enforce SNMPv3 security features where SNMP is required.                                 |
| `VCFA-9X-000312`     |The VMware Cloud Foundation vCenter Server must include only approved trust anchors in trust stores or certificate stores managed by the organization.|
| `VCFA-9X-000327`     |The VMware Cloud Foundation vCenter Server must not configure VLAN Trunking unless Virtual Guest Tagging (VGT) is required and authorized.|
| `VCFA-9X-000330`     |The VMware Cloud Foundation vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List (HCL) by use of an external proxy server.|
| `VCFA-9X-000331`     |The VMware Cloud Foundation vCenter Server must have Mutual Challenge Handshake Authentication Protocol (CHAP) enabled for the vSAN Internet Small Computer System Interface (iSCSI) target service.|
| `VCFA-9X-000332`     |The VMware Cloud Foundation vCenter Server must have new Key Encryption Keys (KEKs) reissued at regular intervals for vSAN encrypted datastore(s).|
| `VCFA-9X-000335`     |The VMware Cloud Foundation vCenter Server Native Key Provider must be backed up with a strong password.                                 |
| `VCFA-9X-000336`     |The VMware Cloud Foundation vCenter Server must require authentication for published content libraries.                                  |
| `VCFA-9X-000337`     |The VMware Cloud Foundation vCenter Server must enable the OVF security policy for content libraries.                                    |
| `VCFA-9X-000338`     |The VMware Cloud Foundation vCenter Server must separate authentication and authorization for administrators.                            |
| `VCFA-9X-000343`     |The VMware Cloud Foundation vCenter Server must enable data in transit encryption for vSAN.                                              |

## Remediating Automation
To remediate VCF Automation an Ansible playbook has been provided that will target Operations appliances over the REST API and configure any supported non-compliant controls.   

### Update Ansible Inventory and Vault with target Automation Server details
In the Ansible inventory file and vault ensure the target Automation server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Automation inventory group and update the automation_1 or automation_vip node as needed.
automation:
  hosts:
    automation_vip:
      ansible_host:
    automation_1:
      ansible_host:
      ansible_user: vmware-system-user
      ansible_password: "{{ var_vault_automation_1_vmware_system_user_password }}"

# Generate an API token for VCF Automation

# A session token can be retrieved in different ways but curl is shown in this example.
# Generate a base64 encoded string from the username:password text. For example:
base64 <<< 'admin:password'
# Replace <base64credential> with the generated text and replace <vcfa_fqdn> with the VCF Automation FQDN.
curl -i -k -X POST -H 'Authorization: Basic <base64credential>' -H 'Accept: application/*;version=40.0' https://<vcfa_fqdn>/cloudapi/1.0.0/sessions/provider

# Alternatively the credentials to generate a session token can be provided as shown below.
# Replace <username:password> with the generated text and replace <vcfa_fqdn> with the VCF Automation FQDN.
curl -i -k -X POST -u "<username:password>" -H 'Accept: application/*;version=40.0' https://<vcfa_fqdn>/cloudapi/1.0.0/sessions/provider

# Capture the token from the returned `x-vmware-vcloud-access-token` header returned and enter this in the Ansible vault in the next steps.

# Update the credentials in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Automation credential variables and update and save (:wq)
var_vault_automation_session_token:
```

### Update Ansible variables for Automation tasks
Update environment specific variable values before running the playbook. In this example the group vars are being updated, see the [VCF 9.x Ansible Playbook Overview](/docs/tutorials/cloud-foundation-9x/ansible-playbook-overview.md) for more details on how variables are structured and for alternative approaches.    

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi group_vars/automation.yml

# Provide the environment values and save (:wq)
# Automation Configuration
automation_defaults_api_version: 'application/*;version=40.0'
automation_defaults_disable_branding_without_login: 'true'
## Enter a list of approved feature flags. Use the display name for the value.
automation_defaults_approved_feature_flags: []
```

### Running the playbook
To remediate all Automation product rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target the Automation automation_1 node in inventory and remediate all rules.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l automation_1 -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on an Automation target in inventory named automation_1.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l automation_1 -v --ask-vault-pass -e @vault_vcf.yml --tags VCFA-9X-000374
```

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFA-9X-000104`     |VMware Cloud Foundation Automation must restrict the ability of individuals to use information systems to launch denial-of-service (DoS) attacks against other information systems.|
| `VCFA-9X-000373`     |VMware Cloud Foundation Automation must include only approved trust anchors in trust stores or certificate stores managed by the organization.|
| `VCFA-9X-000381`     |VMware Cloud Foundation Automation assigned roles and permissions must be verified.                                                      |

## Remediating Operations
To remediate Operations an Ansible playbook has been provided that will target Operations appliances over the REST API and configure any supported non-compliant controls.  

### Update Ansible Inventory and Vault with target Operations server details
In the Ansible inventory file and vault ensure the target Operations server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations inventory group and update the ops_master host.
operations:
  hosts:
    ops_master:
      ansible_host: ops-master.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_operations_master_root_password }}"

# Prepare credentials for VCF Operations
## Replace username and password as well as <vcf_operations_fqdn> with the VCF Operations FQDN.
curl -k -X 'POST' 'https://<vcf_operations_fqdn>/suite-api/api/auth/token/acquire' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"username":"admin", "password":"password"}'

# Capture the token from the returned response and enter this in the Ansible vault in the next steps.

# Update the credentials in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations credential variables and update and save (:wq)
var_vault_operations_session_token:
```

### Running the playbook
To remediate all Operations product rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target the Operations master node in inventory and remediate all rules.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_master -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations node in inventory named ops_master.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_master -v --ask-vault-pass -e @vault_vcf.yml --tags VCFA-9X-000001

# Output example
TASK [operations : VCFA-9X-000001 - Update concurrent sessions setting] *******************************************************************************************************************************************************
changed: [ops_master] => {"access_control_allow_origin": "*", "cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": true, "connection": "Upgrade, close", "content_length": "0", "content_security_policy": "default-src https: wss: data: 'unsafe-inline' 'unsafe-eval'; child-src *; worker-src 'self' blob:", "cookies": {}, "cookies_string": "", "date": "Mon, 19 May 2025 22:30:50 GMT", "elapsed": 0, "expires": "0", "msg": "OK (0 bytes)", "pragma": "no-cache", "redirected": false, "server": "Apache", "status": 201, "strict_transport_security": "max-age=31536000; includeSubDomains", "upgrade": "h2,h2c", "url": "https://ops-master.rainpole.local/suite-api/api/deployment/config/globalsettings/ALLOW_CONCURRENT_LOGIN_SESSIONS/false", "vary": "User-Agent", "x_content_type_options": "nosniff", "x_frame_options": "SAMEORIGIN", "x_request_id": "dVVj3YKJu5aeWgNYjmWkWViZQcAtw0Kk", "x_xss_protection": "1; mode=block"}

TASK [operations : VCFA-9X-000054 - Multifactor authentication] ***************************************************************************************************************************************************************
ok: [ops_master] => {
    "msg": "VCFA-9X-000054 - This control must be manually remediated."
}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
ops_master                 : ok=26   changed=3    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFA-9X-000054`     |VMware Cloud Foundation must use multifactor authentication for access to privileged accounts.                                           |
| `VCFA-9X-000141`     |VMware Cloud Foundation must be configured to forward vSphere logs to a central log server.                                              |
| `VCFA-9X-000292`     |VMware Cloud Foundation Operations must disable unsigned management pack installation.                                                   |
| `VCFA-9X-000346`     |VMware Cloud Foundation Operations must enforce password complexity requirements.                                                        |
| `VCFA-9X-000347`     |VMware Cloud Foundation Operations must display the Standard Mandatory DOD Notice and Consent Banner before logon.                       |
| `VCFA-9X-000348`     |VMware Cloud Foundation Operations must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.|
| `VCFA-9X-000351`     |VMware Cloud Foundation Operations assigned roles and scopes must be verified.                                                           |
| `VCFA-9X-000352`     |VMware Cloud Foundation Operations must enable FIPS-validated cryptography.                                                              |
| `VCFA-9X-000353`     |VMware Cloud Foundation Operations must enable firewall hardening.                                                                       |
| `VCFA-9X-000361`     |VMware Cloud Foundation Operations must include only approved trust anchors in trust stores or certificate stores managed by the organization.|
| `VCFA-9X-000363`     |VMware Cloud Foundation must be configured to forward VCF Operations logs to a central log server.                                       |
| `VCFA-9X-000365`     |VMware Cloud Foundation must be configured to forward VCF Operations Fleet Management logs to a central log server.                      |
| `VCFA-9X-000366`     |VMware Cloud Foundation Operations must compare internal information system clocks with an authoritative time server.                    |
| `VCFA-9X-000368`     |VMware Cloud Foundation Operations must configure Operations for Networks to compare internal information system clocks with an authoritative time server.|
| `VCFA-9X-000369`     |VMware Cloud Foundation Operations must configure Automation to compare internal information system clocks with an authoritative time server.|
| `VCFA-9X-000370`     |VMware Cloud Foundation Operations must configure Identity Broker to compare internal information system clocks with an authoritative time server.|

## Remediating Operations Fleet Management
To remediate Operations Fleet Management an Ansible playbook has been provided that will target Operations appliances over the REST API and configure any supported non-compliant controls.  

### Update Ansible Inventory and Vault with target Operations Fleet Management Server details
In the Ansible inventory file and vault ensure the target Operations Fleet Management server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations Fleet Management inventory group and update the existing host as needed.
operations_fm:
  hosts:
    ops_fm:
      ansible_host: opsfm.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_operations_fm_root_password }}"

# Prepare credentials for VCF Operations Fleet Management
## Generate a base64 encoded string from the username:password text. For example:
base64 <<< 'admin@local:password'

# Capture the token from the returned response and enter this in the Ansible vault in the next steps.

# Update the credentials in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations Fleet Management credential variables and update and save (:wq)
var_vault_operations_fm_api_token:
```

### Update Ansible variables for Operations Fleet Management tasks
Update environment specific variable values before running the playbook. In this example the group vars are being updated, see the [VCF 9.x Ansible Playbook Overview](/docs/tutorials/cloud-foundation-9.x/ansible-playbook-overview) for more details on how variables are structured and for alternative approaches.    

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi group_vars/operations_fm.yml

# Provide the environment specific values and save (:wq)
# NTP Servers - provide a comma separated list with no spaces (i.e., '10.0.0.1,10.0.0.2')
ops_fm_defaults_time_servers: ''
```

### Running the playbook
To remediate all Operations Fleet Management product rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target the Operations Fleet Management node in inventory and remediate all rules.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_fm -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations Fleet Management node in inventory named ops_fm.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_fm -v --ask-vault-pass -e @vault_vcf.yml --tags VCFA-9X-000371

# Output example
TASK [ops_fm : VCFA-9X-000371 - Get authoritative time server] ****************************************************************************************************************************************************************
ok: [ops_fm] => {"ansible_facts": {"discovered_interpreter_python": "/usr/bin/python3.11"}, "cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": false, "connection": "close", "content_security_policy": "script-src 'self'", "content_type": "application/json", "cookies": {"JSESSIONID": "0B28F0ACC36C92D51D6AE23EFA091482"}, "cookies_string": "JSESSIONID=0B28F0ACC36C92D51D6AE23EFA091482", "date": "Tue, 20 May 2025 13:48:49 GMT", "elapsed": 3, "expires": "0", "json": {"dateTime": "Tue May 20 01:48:48 PM UTC 2025", "ntpServerEnabled": true, "ntpServerStarted": true, "ntpServers": "10.0.0.1", "syncWithHost": false}, "lcm_api_version": "8.0, 8.0", "msg": "OK (unknown bytes)", "pragma": "no-cache", "redirected": false, "set_cookie": "JSESSIONID=0B28F0ACC36C92D51D6AE23EFA091482; Path=/; HttpOnly; Secure; HttpOnly; SameSite=Lax", "status": 200, "strict_transport_security": "max-age=31536000; includeSubDomains", "transfer_encoding": "chunked", "url": "https://opsfm.rainpole.local/lcm/lcops/api/v2/settings/system-details/time", "x_content_type_options": "nosniff", "x_frame_options": "DENY", "x_xss_protection": "1; mode=block"}

TASK [ops_fm : VCFA-9X-000371 - Update time server settings] ******************************************************************************************************************************************************************
skipping: [ops_fm] => {"changed": false, "skip_reason": "Conditional result was False"}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
ops_fm                     : ok=4    changed=0    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

### Manually remediate any remaining rules
None at this time.

## Remediating Operations for Logs
To remediate Operations for Logs an Ansible playbook has been provided that will target Operations appliances over the REST API and configure any supported non-compliant controls.   

### Update Ansible Inventory and Vault with target Operations for Logs Server details
In the Ansible inventory file and vault ensure the target Operations for Logs server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations for Logs inventory group and update the ops_logs_1 host with the master node.
operations_logs:
  hosts:
    ops_logs_1:
      ansible_host: opslogs1.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_operations_logs_1_root_password }}"

# Prepare credentials for VCF Operations for Logs
## Replace username and password in the example command and replace <opslogs_fqdn> with the VCF Operations for Logs FQDN.
curl -k -X POST https://<opslogs_fqdn>:9543/api/v2/sessions -d '{"username":"admin", "password":"password", "provider":"Local"}'

# Capture the token from the returned `sessionID` header and enter this in the Ansible vault in the next steps.

# Update the credentials in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations for Logs credential variables and update and save (:wq)
var_vault_operations_logs_api_token:
```

### Update Ansible variables for Operations for Logs tasks
Update environment specific variable values before running the playbook. In this example the group vars are being updated, see the [VCF 9.x Ansible Playbook Overview](/docs/tutorials/cloud-foundation-9x/ansible-playbook-overview.md) for more details on how variables are structured and for alternative approaches.    

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi group_vars/operations_logs.yml

# Provide the environment specific values and save (:wq)
# Time servers to use - provide a comma delimited array, with spaces between entries (i.e., ["10.0.0.1", "10.0.0.2"])
ops_logs_defaults_ntp_servers:
```

### Running the playbook
To remediate all Operations for Logs product rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target the Operations for Logs master node in inventory and remediate all rules.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_logs_1 -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations for Logs node in inventory named ops_logs_1.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_logs_1 -v --ask-vault-pass -e @vault_vcf.yml --tags VCFA-9X-000142

# Output example
TASK [ops_logs : VCFA-9X-000358 - Update session timeout setting] *************************************************************************************************************************************************************
changed: [ops_logs_1] => {"access_control_expose_headers": "X-LI-Build", "changed": true, "connection": "close", "content_length": "0", "cookies": {}, "cookies_string": "", "date": "Tue, 20 May 2025 13:59:38 UTC", "elapsed": 0, "msg": "OK (0 bytes)", "redirected": false, "status": 200, "url": "https://opslogs1.rainpole.local:9543/api/v2/ui/browser-session", "x_li_build": "24695810"}

TASK [ops_logs : VCFA-9X-000367 - Get ntp settings] ***************************************************************************************************************************************************************************
ok: [ops_logs_1] => {"access_control_expose_headers": "X-Content-Type-Options,X-LI-Build,x-li-session-id,x-li-timestamp", "changed": false, "connection": "close", "content_length": "70", "content_type": "application/json; charset=UTF-8", "cookies": {}, "cookies_string": "", "date": "Tue, 20 May 2025 13:59:39 UTC", "elapsed": 0, "json": {"ntpConfig": {"ntpServers": ["25.0.0.1"], "timeReference": "NTP_SERVER"}}, "msg": "OK (70 bytes)", "redirected": false, "status": 200, "url": "https://opslogs1.rainpole.local:9543/api/v2/time/config", "x_content_type_options": "nosniff", "x_li_build": "24695810", "x_li_session_id": "A20d6VZFlFdqsHH7de5rjKzYFIBmCFbUZGI2uuBZWrN97ujvR8rSjeaBBuag52BDpVgzrjBDgezFZs2TJwAj+8QgvyQ+Oxr6IfGEgG/uKHxEwfX0q8GzeElGAozo+Gwk/+NM0nK4IUF6d7p/WN8y", "x_li_timestamp": "1747749579"}

TASK [ops_logs : VCFA-9X-000367 - Update time settings] ***********************************************************************************************************************************************************************
skipping: [ops_logs_1] => {"changed": false, "skip_reason": "Conditional result was False"}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
ops_logs_1                 : ok=18   changed=1    unreachable=0    failed=0    skipped=4    rescued=0    ignored=0
```

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFA-9X-000196`     |VMware Cloud Foundation Operations for Logs must protect the confidentiality and integrity of transmitted information.                   |
| `VCFA-9X-000253`     |VMware Cloud Foundation Operations for Logs must enable FIPS-validated cryptography.                                                     |
| `VCFA-9X-000357`     |VMware Cloud Foundation Operations for Logs must enforce password complexity requirements.                                               |
| `VCFA-9X-000359`     |VMware Cloud Foundation Operations for Logs must display the Standard Mandatory DOD Notice and Consent Banner before logon.              |
| `VCFA-9X-000360`     |VMware Cloud Foundation Operations for Logs assigned roles and permissions must be verified.                                             |

## Remediating Operations for Networks
To remediate Operations for Networks an Ansible playbook has been provided that will target Operations appliances over the REST API and configure any supported non-compliant controls.   

### Update Ansible Inventory and Vault with target Operations for Networks Server details
In the Ansible inventory file and vault ensure the target Operations for Networks server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations for Networks inventory group and update the ops_networks_platform_1 node as needed.
operations_networks_platform:
  hosts:
    ops_networks_platform_1:
      ansible_host: opsnet1.rainpole.local
      ansible_user: support
      ansible_password: "{{ var_vault_operations_networks_platform_1_support_password }}"
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_user: root

# Prepare credentials for VCF Operations for Networks
## Replace username and password in the example command and replace <ops_fqdn> with the VCF Operations for Networks FQDN.
curl -k -X POST https://<ops_fqdn>/api/ni/auth/token -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"username": "admin@local",  "password": "password", "domain": {"domain_type": "LOCAL", "value": ""}}'

# Capture the token from the returned `sessionID` header and enter this in the Ansible vault in the next steps.

# Update the credentials in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations for Networks credential variables and update and save (:wq)
var_vault_operations_networks_api_token:
```

### Running the playbook
To remediate all Operations for Networks product rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target the Operations for Logs master node in inventory and remediate all rules.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_networks_platform_1 -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations for Logs node in inventory named ops_networks_platform_1.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_networks_platform_1 -v --ask-vault-pass -e @vault_vcf.yml --tags VCFA-9X-000379

# Output example
TASK [ops_net : VCFA-9X-000379 - Get login banner settings] *******************************************************************************************************************************************************************
ok: [ops_networks_platform_1] => {"ansible_facts": {"discovered_interpreter_python": "/usr/bin/python3.11"}, "cache_control": "no-cache, no-store, must-revalidate", "changed": false, "connection": "close", "cookies": {}, "cookies_string": "", "date": "Tue, 20 May 2025 14:20:08 GMT", "elapsed": 0, "msg": "OK (unknown bytes)", "pragma": "no-cache", "redirected": false, "status": 200, "strict_transport_security": "max-age=31536000; includeSubDomains", "transfer_encoding": "chunked", "url": "https://opsnet1.rainpole.local/api/ni/settings/loginBanner", "vary": "Accept-Encoding, Accept-Encoding", "x_content_type_options": "nosniff", "x_frame_options": "sameorigin", "x_xss_protection": "1; mode=block"}

TASK [ops_net : VCFA-9X-000379 - Update login banner settings] ****************************************************************************************************************************************************************
changed: [ops_networks_platform_1] => {"cache_control": "no-cache, no-store, must-revalidate", "changed": true, "connection": "close", "content_length": "1481", "content_type": "application/json", "cookies": {}, "cookies_string": "", "date": "Tue, 20 May 2025 14:20:08 GMT", "elapsed": 0, "json": {"is_enabled": true, "login_message_banner": "", "user_consent_description": "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\n    By using this IS (which includes any device attached to this IS), you consent to the following conditions:\n    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n    -At any time, the USG may inspect and seize data stored on this IS.\n    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.", "user_consent_title": "The Standard Mandatory DOD Notice and Consent Banner"}, "msg": "OK (1481 bytes)", "pragma": "no-cache", "redirected": false, "status": 201, "strict_transport_security": "max-age=31536000; includeSubDomains", "url": "https://opsnet1.rainpole.local/api/ni/settings/loginBanner", "x_content_type_options": "nosniff", "x_frame_options": "sameorigin", "x_xss_protection": "1; mode=block"}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
ops_networks_platform_1    : ok=10   changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFA-9X-000024`     |VMware Cloud Foundation Operations for Networks must enable the generation of audit records with sufficient information to support investigations.|
| `VCFA-9X-000376`     |VMware Cloud Foundation Operations for Networks must terminate sessions after 15 minutes of inactivity.                                  |
| `VCFA-9X-000377`     |VMware Cloud Foundation Operations for Networks must disable automatic certificate validation for data sources.                          |
| `VCFA-9X-000378`     |VMware Cloud Foundation Operations for Networks must enable FIPS-validated cryptography for external connections.                        |
| `VCFA-9X-000380`     |VMware Cloud Foundation Operations for Networks assigned roles and permissions must be verified.                                         |
| `VCFA-9X-000386`     |VMware Cloud Foundation Operations for Networks must be configured to forward logs to a central log server.                              |

## Remediating Operations HCX
To remediate Operations HCX an Ansible playbook has been provided that will target Operations appliances over the REST API and configure any supported non-compliant controls.   

### Update Ansible Inventory and Vault with target Operations HCX Server details
In the Ansible inventory file and vault ensure the target Operations HCX server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the Operations HCX inventory group and update the ops_hcx_mgr node as needed.
operations_hcx_mgr:
  hosts:
    ops_hcx_mgr:
      ansible_host: opshcxmgr.rainpole.local
      ansible_user: admin
      ansible_password: "{{ var_vault_operations_hcx_mgr_admin_password }}"
      ansible_become: true
      ansible_become_method: su
      ansible_become_user: root
      ansible_become_password: "{{ var_vault_operations_hcx_mgr_root_password }}"

# Prepare credentials for VCF Operations HCX
## Generate a base64 encoded string from the username:password text. For example:
base64 <<< 'admin@local:password'

# Capture the value returned and enter this in the Ansible vault in the next steps.

# Update the credentials in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the Operations for Networks credential variables and update and save (:wq)
var_vault_operations_hcx_session_token:
```

### Update Ansible variables for Operations HCX tasks
Update environment specific variable values before running the playbook. In this example the group vars are being updated, see the [VCF 9.x Ansible Playbook Overview](/docs/tutorials/cloud-foundation-9.x/ansible-playbook-overview) for more details on how variables are structured and for alternative approaches.    

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi group_vars/operations_hcx_mgr.yml

# Provide the environment values and save (:wq)
# Provide an array of authorized NTP servers
ops_hcx_defaults_time_servers: []
```

### Running the playbook
To remediate all Operations HCX product rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target the Operations HCX manager node in inventory and remediate all rules.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_hcx_mgr -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single Operations HCX manager node in inventory named ops_hcx_mgr.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l ops_hcx_mgr -v --ask-vault-pass -e @vault_vcf.yml --tags VCFA-9X-000383
```

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFA-9X-000382`     |VMware Cloud Foundation Operations HCX must be configured to forward logs to a central log server.                                       |
| `VCFA-9X-000384`     |VMware Cloud Foundation Operations HCX must only allow the use of DOD PKI established certificate authorities for verification of the establishment of protected sessions.|
| `VCFA-9X-000385`     |VMware Cloud Foundation Operations HCX must include only approved trust anchors in trust stores or certificate stores managed by the organization.|

## Remediating SDDC Manager
To remediate SDDC Manager an Ansible playbook has been provided that will target Operations appliances over the REST API and configure any supported non-compliant controls.   

### Update Ansible Inventory and Vault with target SDDC Manager Server details
In the Ansible inventory file and vault ensure the target SDDC Manager server details are correct.

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi inventory_vcf.yml

# Locate the SDDC Manager inventory group and update the ops_hcx_mgr node as needed.
sddcmanager:
  hosts:
    sddcmgr:
      ansible_host: sddcmanager.rainpole.local
      ansible_user: root
      ansible_password: "{{ var_vault_sddcmgr_root_password }}"

# Prepare credentials for VCF SDDC Manager
## To generate a session token through the UI go to the VCF SDDC Manager interface >> Developer Center >> API Explorer.  
## Find the `Tokens' category and expand `POST` method. Enter the credentials for the target user in the body as shown below and click Execute.

{
  "password": "mypassword",
  "username": "myusername"
}

## A token can also be generated via curl or other REST client. A curl example is shown below.
curl -k 'https://<sddcmgr_fqdn>/v1/tokens' -i -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -d '{
  "username" : "administrator@vsphere.local",
  "password" : "mypassword"
}'

# Capture the value returned in the `accessToken` field and enter this in the Ansible vault in the next steps.

# Update the credentials in Ansible Vault
# Encrypt the example vault if not already done
ansible-vault encrypt vault_vcf.yml

# Edit the vault
ansible-vault edit vault_vcf.yml

# Locate the SDDC Manager credential variables and update and save (:wq)
var_vault_sddcmgr_bearer_token:
```

### Update Ansible variables for SDDC Manager tasks
Update environment specific variable values before running the playbook. In this example the group vars are being updated, see the [VCF 9.x Ansible Playbook Overview](/docs/tutorials/cloud-foundation-9.x/ansible-playbook-overview) for more details on how variables are structured and for alternative approaches.    

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Open the inventory file for editing. Replace the name if using a different inventory file for the environment.
vi group_vars/sddcmanager.yml

# Provide the environment values and save (:wq)
# ENABLED or DISABLED
sddcmgr_defaults_basic_auth: 'DISABLED'
```

### Running the playbook
To remediate all SDDC Manager product rules, follow the example below:

```bash
# Navigate to the Ansible playbook folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/ansible/vmware-cloud-foundation-stig-ansible-hardening/

# Prior to running please ensure the Ansible inventory, vault, and any environment specific variables are updated.  Enter the vault password when prompted.
# This command will target the SDDC Manager manager node in inventory and remediate all rules.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l sddcmgr -v --ask-vault-pass -e @vault_vcf.yml

# Run a subset of STIG rules by STIG ID on a single SDDC Manager manager node in inventory named sddcmgr.
ansible-playbook playbook_api.yml -i inventory_vcf.yml -l sddcmgr -v --ask-vault-pass -e @vault_vcf.yml --tags VCFA-9X-000355

# Output example
TASK [sddcmgr : VCFA-9X-000355 - Update Basic Auth] ***************************************************************************************************************************************************************************
changed: [sddcmgr] => {"cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": true, "connection": "close", "content_length": "0", "cookies": {}, "cookies_string": "", "date": "Tue, 20 May 2025 16:07:54 GMT", "elapsed": 0, "expires": "0", "msg": "OK (0 bytes)", "pragma": "no-cache", "redirected": false, "referrer_policy": "no-referrer", "server": "nginx", "status": 200, "strict_transport_security": "max-age=15768000", "url": "https://sddcmanager.rainpole.local/v1/sddc-manager", "x_content_type_options": "nosniff, nosniff", "x_frame_options": "DENY, SAMEORIGIN", "x_xss_protection": "0"}

PLAY RECAP ********************************************************************************************************************************************************************************************************************
sddcmgr                    : ok=9    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

### Manually remediate any remaining rules
The following rules require manual remediation and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFA-9X-000354`     |VMware Cloud Foundation SDDC Manager assigned roles and permissions must be verified.                                                    |
| `VCFA-9X-000356`     |VMware Cloud Foundation SDDC Manager must configure the API admin account.                                                               |
| `VCFA-9X-000364`     |VMware Cloud Foundation SDDC Manager must be configured to forward logs to a central log server.                                         |
| `VCFA-9X-000372`     |VMware Cloud Foundation SDDC Manager must compare internal information system clocks with an authoritative time server.                  |

## Functional Testing
Perform any needed functional testing to ensure the functionality and operation of the environment remain intact.

## Rerun auditing after remediation
To audit VCF application STIG rules post-remediation rerun the auditing steps [here](/docs/tutorials/cloud-foundation-9x/product/vcf-application/audit9-app/audit9-app.md).
