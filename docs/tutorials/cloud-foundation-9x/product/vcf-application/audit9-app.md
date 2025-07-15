---
title: "Audit VCF 9.x"
weight: 1
description: >
  Auditing VCF Application rules 9.x for STIG Compliance
---
## Overview
This tutorial covers auditing the VCF Application STIG in VCF deployments which includes product rules for the following components:
  - Automation
  - Identity Broker
  - Operations
  - Operations Fleet Management
  - Operations for Logs
  - Operations for Networks
  - Operations HCX
  - SDDC Manager
  - vCenter

Auditing these components can occur individually or together.  


The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.


### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* InSpec/Cinc Auditor 6.8.24
* InSpec train-vmware 1.0.0
* SAF CLI 1.4.20
* STIG Viewer 2.17
* A VCF 9.0.0.0+ environment 
* PowerShell 7.4.7
* VCF PowerCLI 9.0.0.0+
* VCF STIG Helpers PowerShell module 1.0.1+

#### VCF STIG Helpers PowerShell Module
The VCF STIG Helpers PowerShell module provides additional supporting functions to the scripts provided here and for the vSphere InSpec profiles.  

The functions provided are: `Set-vCenterCredentials` `Get-vCenterCredentials` `Set-PowerCLICredential` `Get-PowerCLICredentialUsername` `Get-PowerCLICredentialPassword` `Write-Message` `Write-Header` `Test-PowerCLI` `Test-vCenter` `Test-ESX`

### Assumptions
* Commands are being run from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* CINC Auditor is used in lieu of InSpec. If InSpec is used replace `cinc-auditor` with `inspec` when running commands.

### Install the custom VMware transport for InSpec
To extend the functionality of the VMware transport that ships with InSpec a custom one has been created that also incorporates the `VMware.Vsphere.SsoAdmin` module to extend automation coverage to the vCenter SSO STIG controls.  

To install the plugin that is included with the `vmware-cloud-foundation-stig-baseline` profile, do the following:

```
# Install the custom train-vmware plugin. Update the path to the gem as needed. The command will be the same on Windows and Linux.
> cinc-auditor plugin install /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/train-vmware-1.0.0.gem

# To verify the installation
> cinc-auditor plugin list

┌────────────────────────────────────────┬─────────┬──────────────┬─────────┬────────────────────────────────────────────────────────────────────────┐
│              Plugin Name               │ Version │     Via      │ ApiVer  │                              Description                               │
├────────────────────────────────────────┼─────────┼──────────────┼─────────┼────────────────────────────────────────────────────────────────────────┤
│ inspec-compliance                      │ 6.8.24  │ core         │ 2       │ Plugin to perform operations with Chef Automate                        │
│ inspec-habitat                         │ 6.8.24  │ core         │ 2       │ Plugin to create/upload habitat package                                │
│ inspec-init                            │ 6.8.24  │ core         │ 2       │ Plugin for scaffolding profile, plugin or a resource                   │
│ inspec-license                         │ 6.8.24  │ core         │ 2       │ Plugin to list user licenses.                                          │
│ inspec-parallel                        │ 6.8.24  │ core         │ 2       │ Plugin to handle parallel InSpec scan operations over multiple targets │
│ inspec-plugin-manager-cli              │ 6.8.24  │ core         │ 2       │ CLI plugin for InSpec                                                  │
│ inspec-reporter-html2                  │ 6.8.24  │ core         │ 2       │ Improved HTML reporter plugin                                          │
│ inspec-reporter-json-min               │ 6.8.24  │ core         │ 2       │ Json-min json reporter plugin                                          │
│ inspec-reporter-junit                  │ 6.8.24  │ core         │ 2       │ JUnit XML reporter plugin                                              │
│ inspec-sign                            │ 6.8.24  │ core         │ 2       │                                                                        │
│ inspec-streaming-reporter-progress-bar │ 6.8.24  │ core         │ 2       │ Displays a real-time progress bar and control title as output          │
│ inspec-supermarket                     │ 6.8.24  │ core         │ 0       │                                                                        │
│ train-aws                              │ 0.2.41  │ gem (system) │ train-1 │ AWS API Transport for Train                                            │
│ train-habitat                          │ 0.2.22  │ gem (system) │ train-1 │ Habitat API Transport for Train                                        │
│ train-kubernetes                       │ 0.2.1   │ gem (system) │ train-1 │ Train Kubernetes                                                       │
│ train-vmware                           │ 1.0.0   │ gem (user)   │ train-1 │ Train Plugin for VMware PowerCLI                                       │
│ train-winrm                            │ 0.2.13  │ gem (system) │ train-1 │ Windows WinRM API Transport for Train                                  │
└────────────────────────────────────────┴─────────┴──────────────┴─────────┴────────────────────────────────────────────────────────────────────────┘
 17 plugin(s) total
```

**Note - Plugins are installed per user and must be installed as the user running InSpec.**

## Auditing VCF

### Setup Connection to vCenter
This profile uses a custom VMware InSpec transport(train) to run PowerCLI commands that must be installed in order for this profile to run. This custom transport is derived from the default InSpec VMware transport and extends it by adding support for the `VMware.Vsphere.SsoAdmin` PowerShell module as well as an optional connection method using a PowerShell credential file.  

Connection Options:

  - Provide vCenter credentials via environment variables
    - Take care to clear the history and close the PowerShell session to avoid any credentials left in memory/history if using this option.
  - Create a PowerShell credential file and then provide the file name via an environment variable
    - For more information on exporting credentials to XML see [Export-Clixml](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml?view=powershell-7.5).

`Export-Clixml` only exports encrypted credentials on Windows. On non-Windows operating systems such as macOS and Linux, credentials are exported as plain text stored as a Unicode character array. This provides some obfuscation but does not provide encryption.


#### Connecting via username/password
From a PowerShell session create the following environment variables:

```
powershell
#Enter PowerShell
pwsh

$env:VISERVER="vcenter.rainpole.local"
$env:VISERVER_USERNAME="Administrator@vsphere.local"
$env:VISERVER_PASSWORD="password"
# For PowerShell Core only
$env:NO_COLOR=$true
```

*Note: If the password includes a single tick (') it must be substituted with four ticks ('''') in order for it to be properly escaped all the way through the process.*

#### Connecting via a PowerShell Credential file
From a PowerShell session create a PowerShell credential file:

```
# Enter PowerShell
pwsh

# Navigate to the profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere

# Create a PowerShell credential file and provide a username and password with sufficient privileges to vCenter
Set-vCenterCredentials -OutputFile vcentercreds.xml

# Example output
PowerShell credential request
Enter the username and password for vCenter server ''.
These credentials will be stored securely at 'vcentercreds.xml'.
User: administrator@vsphere.local
Password for user administrator@vsphere.local: ********************

Credentials saved to: vcentercreds.xml

UserName                                        Password
--------                                        --------
administrator@vsphere.local System.Security.SecureString

# Update environment variables for connection
$env:VISERVER="vcenter.rainpole.local"
$env:PCLICREDFILE="/usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/vcentercreds.xml"

# For PowerShell Core only (Not necessary on STIG Tools Appliance)
$env:NO_COLOR=$true

# Leave the PowerShell session open for the remaining steps
```

**Note: If the `PCLICREDFILE` environment variable exists it will take precedence over username and password when attempting the connection to vCenter.**

#### Generate API tokens for VCF Components
An API token is required in order for auditing to interact with the API for the following components:
  - Automation
  - Operations
  - Operations Fleet Management
  - Operations for Logs
  - Operations for Networks
  - Operations HCX
  - SDDC Manager

Once gathered these tokens will be specified in the next step in the inputs provided to the InSpec profile.

**Note: These tasks are time sensitive as the API tokens will expire.**

If some components are not deployed then skip those steps.  

```
# Generate an API token for VCF Automation

## A session token can be retrieved in different ways but curl is shown in this example.
## Generate a base64 encoded string from the username:password text. For example:
base64 <<< 'admin:password'
## Replace <base64credential> with the generated text and replace <vcfa_fqdn> with the VCF Automation FQDN.
curl -i -k -X POST -H 'Authorization: Basic <base64credential>' -H 'Accept: application/*;version=40.0' https://<vcfa_fqdn>/cloudapi/1.0.0/sessions/provider

## Alternatively the credentials to generate a session token can be provided as shown below.
## Replace <username:password> with the generated text and replace <vcfa_fqdn> with the VCF Automation FQDN.
curl -i -k -X POST -u "<username:password>" -H 'Accept: application/*;version=40.0' https://<vcfa_fqdn>/cloudapi/1.0.0/sessions/provider

## Capture the token from the returned `x-vmware-vcloud-access-token` header and enter this in the inputs file used for the value of the `automation_sessionToken` input.

# Prepare credentials for VCF Operations Fleet Management
## Generate a base64 encoded string from the username:password text. For example:
base64 <<< 'admin@local:password'

## Capture the value returned and enter this in the inputs file used for the value of the `fm_apitoken` input.

# Prepare credentials for VCF Operations
## Replace username and password as well as <vcf_operations_fqdn> with the VCF Operations FQDN.
curl -k -X 'POST' 'https://<vcf_operations_fqdn>/suite-api/api/auth/token/acquire' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"username":"admin", "password":"password"}'

## Capture the token from the returned response and enter this in the inputs file used for the value of the `operations_apitoken` input.

# Prepare credentials for VCF Operations for Logs
## Replace username and password in the example command and replace <opslogs_fqdn> with the VCF Operations for Logs FQDN.
curl -k -X POST https://<opslogs_fqdn>:9543/api/v2/sessions -d '{"username":"admin", "password":"password", "provider":"Local"}'

## Capture the token from the returned `sessionID` header and enter this in the inputs file used for the value of the `opslogs_apitoken` input.

# Prepare credentials for VCF Operations for Networks
## Replace username and password in the example command and replace <ops_fqdn> with the VCF Operations for Networks FQDN.
curl -k -X POST https://<ops_fqdn>/api/ni/auth/token -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"username": "admin@local",  "password": "password", "domain": {"domain_type": "LOCAL", "value": ""}}'

## Capture the token from the returned `sessionID` header and enter this in the inputs file used for the value of the `opsnet_apitoken` input.

# Prepare credentials for VCF SDDC Manager
## To generate a session token through the UI go to the VCF SDDC Manager interface >> Developer Center >> API Explorer.  
## Find the `Tokens` category and expand the `POST` method. Enter the credentials for the target user in the body as shown below and click Execute.

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

## Capture the token from the returned response in the `accessToken` field and enter this in the inputs file used for the value of the `sddcmgr_sessionToken` input.

# Prepare credentials for VCF Operations HCX
## Generate a base64 encoded string from the username:password text. For example:
base64 <<< 'admin@local:password'

## Capture the value returned and enter this in the inputs file used for the value of the `opshcx_apiToken` input.
```

### Update profile inputs
Included in the `vmware-cloud-foundation-stig-baseline` is an example `inputs-example.yml` file with inputs needed to run the audit.  This is used to provide InSpec with values specific to the environment being audited.

Update profile inputs for the target environment.

```
# Navigate to the InSpec profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/

# Edit the example inputs file or create a new one
vi inputs-example.yml

# SDDC Manager Inputs
# Enter target SDDC Manager URL IP or FQDN.
sddcmgr_url: ''
# Enter session token for API authentication.
sddcmgr_sessionToken: ''
# Enter a list of users and their authorized roles to validate.
sddcmgr_authorizedPermissions:
  - user: 'administrator@vsphere.local'
    role: 'Administrator'
  - user: 'vsphere.local\sddcadmins'
    role: 'Administrator'

# vCenter inputs
## Enter an array of authorized NTP servers
vcenter_ntpServers: []
## If IpFix is used enter an array of collector addresses that are authorized.
vcenter_ipfixCollectorAddresses: []
## If any portgroups are authorized to be configured for trunking provide an array of portgroup names.
vcenter_allowedTrunkingPortgroups: []
## Array of authorized users that should be in the SystemConfiguration.BashShellAdministrators SSO group.
vcenter_bashShellAdminUsers:
  - 'Administrator'
## Array of authorized groups that should be in the SystemConfiguration.BashShellAdministrators SSO group.
vcenter_bashShellAdminGroups: []
## Array of authorized port mirroring sessions by session name.
vcenter_portMirrorSessions: []

# VM inputs
# Choose whether to scan a single vm, all vms in a cluster, or all vms in vCenter. Precedence is allvms > cluster > single vm if multiple values are provided.
vm_Name: ''
vm_cluster: ''
vm_allvms: false

# Operations
# Enter target VCF Operations URL IP or FQDN.
operations_apihostname: ''
# Enter token for API authentication.
operations_apitoken: ''

# Automation
# Enter target VCF Automation URL IP or FQDN.
automation_url: ''
# Enter bearer token for API authentication.
automation_sessionToken: ''
# Enter an array of trusted certificate common names that are validated and trusted. The internal Automation CAs are provided here by default.
automation_trustedCertificateCNs:
  - 'tenant-manager-0.tenant-manager.prelude.svc.cluster.local'
  - 'tenant-manager-1.tenant-manager.prelude.svc.cluster.local'
  - 'tenant-manager-2.tenant-manager.prelude.svc.cluster.local'
  - 'vcf-cluster-ca'
  - 'CA'
  - 'VCF Operations Fleet Management Locker CA'
# Enter an array of feature flags that are approved to be enabled
automation_approvedFeatureFlags: []

# Fleet Management
# Enter target Fleet Management URL IP or FQDN.
fm_apihostname: ''
# Enter bearer token for API authentication.
fm_apitoken: ''
# Enter an array of trusted certificate common names that are validated and trusted. The internal Automation CAs are provided here by default.
fm_ntpServers: []

# Operations for Logs
# Enter target VCF Operations for Logs URL IP or FQDN.
opslogs_apihostname: ''
# Enter api token for API authentication.
opslogs_apitoken: ''
# Enter an array of NTP servers.
opslogs_ntpServers: []

# Operations for Networks
# Enter target VCF Operations for Networks URL IP or FQDN.
opsnet_apihostname: ''
# Enter api token for API authentication.
opsnet_apitoken: ''
# Enter the environment specific syslog server Operations for Networks should be forwarding logs to.
opsnet_syslogServers: []

# Operations HCX
# Enter target VCF Operations HCX Manager URL IP or FQDN.
opshcx_url: ''
# Enter api token for API authentication.
opshcx_apiToken: ''
# Enter an array of NTP servers.
opshcx_ntpServers: []
```

### Run the audit
In this example all VCF application rules will be audited, specifying an inputs file, enabling enhanced outcomes in InSpec, and outputting a report to the CLI and to a JSON file.  

```
# Navigate to the InSpec profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/application

# Run the audit
cinc-auditor exec . -t vmware:// --show-progress --enhanced-outcomes --input-file ../inputs-example.yml --reporter cli json:/tmp/reports/VCF_9_Application_Report.json

# Shown below is the last part of the output at the CLI.
Profile Summary: 119 successful controls, 25 control failures, 36 controls not reviewed, 6 controls not applicable, 0 controls have error
Test Summary: 208 successful, 42 failures, 43 skipped
```

In this example a single component of VCF and its associated application rules will be audited, specifying an inputs file, enabling enhanced outcomes in InSpec, and outputting a report to the CLI and to a JSON file.  

```
# Navigate to the InSpec profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/vcenter

# Run the audit
cinc-auditor exec . -t vmware:// --show-progress --enhanced-outcomes --input-file ../../inputs-example.yml --reporter cli json:/tmp/reports/VCF_9_Application_vCenter_Report.json
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

### Update the target details in the metadata file
First update the target hostname, hostip, hostmac, and hostfqdn fields in the `saf_cli_hdf2ckl_metadata.json` metadata file

```
# Update the saf_cli_hdf2ckl_metadata.json file
vi /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/saf_cli_hdf2ckl_metadata.json

"hostname": "many.rainpole.local",
"hostip": "10.1.1.20",
"hostmac": "00:00:00:00:00:00",
"hostfqdn": "many.rainpole.local",
```

### Run SAF CLI to create the CKL file
The following command will convert the json result from the InSpec audit into a STIG Checklist file and ensure the correct metadata is inserted so that it displays correctly in STIG Viewer.  

```
# Convert the InSpec report to a STIG Checklist
saf convert hdf2ckl -i /tmp/reports/VCF_9_Application_Report.json -o /tmp/reports/VCF_9_Application_Report.ckl -m /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/saf_cli_hdf2ckl_metadata.json
```

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  
![STIG Viewer Checklist](../../../images/app_audit9_ckl_screenshot.png)

## Manually audit rules
The following rules require manual auditing and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFA-9X-000018`     |The VMware Cloud Foundation vCenter Server must display the Standard Mandatory DOD Notice and Consent Banner before logon.               |
| `VCFA-9X-000024`     |VMware Cloud Foundation Operations for Networks must enable the generation of audit records with sufficient information to support investigations.|
| `VCFA-9X-000051`     |VMware Cloud Foundation vCenter Server client plugins must be verified.                                                                  |
| `VCFA-9X-000054`     |VMware Cloud Foundation must use multifactor authentication for access to privileged accounts.                                           |
| `VCFA-9X-000082`     |The VMware Cloud Foundation vCenter Server must terminate sessions after 15 minutes of inactivity.                                       |
| `VCFA-9X-000090`     |VMware Cloud Foundation vCenter Server assigned roles and permissions must be verified.                                                  |
| `VCFA-9X-000104`     |VMware Cloud Foundation Automation must restrict the ability of individuals to use information systems to launch denial-of-service (DoS) attacks against other information systems.|
| `VCFA-9X-000141`     |VMware Cloud Foundation must be configured to forward vSphere logs to a central log server.                                              |
| `VCFA-9X-000190`     |VMware Cloud Foundation must only allow the use of DOD PKI established certificate authorities for verification of the establishment of protected sessions.|
| `VCFA-9X-000196`     |VMware Cloud Foundation Operations for Logs must protect the confidentiality and integrity of transmitted information.                   |
| `VCFA-9X-000257`     |The VMware Cloud Foundation vCenter Server must enforce SNMPv3 security features where SNMP is required.                                 |
| `VCFA-9X-000292`     |VMware Cloud Foundation Operations must disable unsigned management pack installation.                                                   |
| `VCFA-9X-000312`     |The VMware Cloud Foundation vCenter Server must include only approved trust anchors in trust stores or certificate stores managed by the organization.|
| `VCFA-9X-000332`     |The VMware Cloud Foundation vCenter Server must have new Key Encryption Keys (KEKs) reissued at regular intervals for vSAN encrypted datastore(s).|
| `VCFA-9X-000335`     |The VMware Cloud Foundation vCenter Server Native Key Provider must be backed up with a strong password.                                 |
| `VCFA-9X-000346`     |VMware Cloud Foundation Operations must enforce password complexity requirements.                                                        |
| `VCFA-9X-000347`     |VMware Cloud Foundation Operations must display the Standard Mandatory DOD Notice and Consent Banner before logon.                       |
| `VCFA-9X-000348`     |VMware Cloud Foundation Operations must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.|
| `VCFA-9X-000351`     |VMware Cloud Foundation Operations assigned roles and scopes must be verified.                                                           |
| `VCFA-9X-000352`     |VMware Cloud Foundation Operations must enable FIPS-validated cryptography.                                                              |
| `VCFA-9X-000353`     |VMware Cloud Foundation Operations must enable firewall hardening.                                                                       |
| `VCFA-9X-000357`     |VMware Cloud Foundation Operations for Logs must enforce password complexity requirements.                                               |
| `VCFA-9X-000360`     |VMware Cloud Foundation Operations for Logs assigned roles and permissions must be verified.                                             |
| `VCFA-9X-000361`     |VMware Cloud Foundation Operations must include only approved trust anchors in trust stores or certificate stores managed by the organization.|
| `VCFA-9X-000364`     |VMware Cloud Foundation SDDC Manager must be configured to forward logs to a central log server.                                         |
| `VCFA-9X-000365`     |VMware Cloud Foundation must be configured to forward VCF Operations Fleet Management logs to a central log server.                      |
| `VCFA-9X-000366`     |VMware Cloud Foundation Operations must compare internal information system clocks with an authoritative time server.                    |
| `VCFA-9X-000368`     |VMware Cloud Foundation Operations must configure Operations for Networks to compare internal information system clocks with an authoritative time server.|
| `VCFA-9X-000369`     |VMware Cloud Foundation Operations must configure Automation to compare internal information system clocks with an authoritative time server.|
| `VCFA-9X-000370`     |VMware Cloud Foundation Operations must configure Identity Broker to compare internal information system clocks with an authoritative time server.|
| `VCFA-9X-000372`     |VMware Cloud Foundation SDDC Manager must compare internal information system clocks with an authoritative time server.                  |
| `VCFA-9X-000376`     |VMware Cloud Foundation Operations for Networks must terminate sessions after 15 minutes of inactivity.                                  |
| `VCFA-9X-000377`     |VMware Cloud Foundation Operations for Networks must disable automatic certificate validation for data sources.                          |
| `VCFA-9X-000378`     |VMware Cloud Foundation Operations for Networks must enable FIPS-validated cryptography for external connections.                        |
| `VCFA-9X-000380`     |VMware Cloud Foundation Operations for Networks assigned roles and permissions must be verified.                                         |
| `VCFA-9X-000381`     |VMware Cloud Foundation Automation assigned roles and permissions must be verified.                                                      |
| `VCFA-9X-000382`     |VMware Cloud Foundation Operations HCX must be configured to forward logs to a central log server.                                       |
| `VCFA-9X-000384`     |VMware Cloud Foundation Operations HCX must only allow the use of DOD PKI established certificate authorities for verification of the establishment of protected sessions.|
| `VCFA-9X-000385`     |VMware Cloud Foundation Operations HCX must include only approved trust anchors in trust stores or certificate stores managed by the organization.|

## Apply Manual Attestations to InSpec Report (Optional)
Optionally a manual attestation file can be created and applied to the InSpec report to insert attestations for any rules that require manual auditing so that the status can be properly reported together with the automated results.  

### Update/Create attestation file and apply to report
An example attestation file has been provided that includes all known manually audited rules.  Update the description, status, and updated_by fields as needed.

```
# Update attestation file
vi /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/attestations-example.yml

- control_id: VCFA-9X-000018
  explanation: 'Add explanation here and update status to passed or failed.'
  frequency: 3y
  status: passed
  updated_by: Chris Kringle

# Apply attestations to report
saf attest apply -i /tmp/reports/VCF_9_Application_Report.json /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/attestations-example.yml -o /tmp/reports/VCF_9_Application_Report_with_attestations.json
```

## Next
If needed proceed to the remediation tutorial for VCF Application rules [here](/docs/tutorials/cloud-foundation-9.x/product/vcf-application/remediate9-app/).
