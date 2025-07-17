# Remediate ESX 9.0.0.0

## Overview
This tutorial covers remediating ESX hosts in VCF deployments.  

For the best experience, prior to using the STIG automation provided here please ensure you:

- Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
- Have an understanding of PowerShell and PowerCLI.
- Have a back out plan so that the changes can be rolled back if necessary.
- Have read the [PowerCLI Overview](/docs/automation-tools/powercli/).

**Failure to do so can result in unintended behavior in the environment.**  

The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* SAF CLI 1.4.20
* STIG Viewer 2.17
* A VCF 9.0.0.0+ environment
* PowerShell Core 7.4.7/PowerShell 5.1
* VCF PowerCLI 9.0.0.0+
* VCF STIG Helpers PowerShell module 1.0.1+

#### VCF STIG Helpers PowerShell Module
The VCF STIG Helpers PowerShell module provides additional supporting functions to the scripts provided here and for the vSphere InSpec profiles.  

The functions provided are: `Set-vCenterCredentials` `Get-vCenterCredentials` `Set-PowerCLICredential` `Get-PowerCLICredentialUsername` `Get-PowerCLICredentialPassword` `Write-Message` `Write-Header` `Test-PowerCLI` `Test-vCenter` `Test-ESX`

#### Included Scripts
`VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1` - Global variables used throughout all scripts.  
`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner_Attestations_Example.yml` - Example attestation file for the ESX InSpec runner script.  
`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner.ps1` - Audits target ESX hosts and facilitates creating accreditation artifacts that would require a more manual process with InSpec/CINC alone.  
`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1` - Variables specific to ESX remediation. Environment specific, rule enablement/disablement, expected STIG values, default values for revert workflow.  
`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1` - Remediation script for ESX.  

### Assumptions
* Commands are being run from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.

## Remediating ESX
Prior to running any scripts it is recommended to familiarize yourself with the scripts and the required parameters as well as test them out in a non-production environment.  

### Common Parameters
The follow parameters are available in all remediation scripts.  

|   Parameter Name  |       Default Value       |                                     Description                                |          Type         |
|-------------------|---------------------------|--------------------------------------------------------------------------------|-----------------------|
| `vccred`          |`None`                     |PowerShell credential object for use in connecting to the target vCenter server.|`PowerShell Credential`|
| `NoSafetyChecks`  |`$false`                   |Skip safety checks to verify PowerCLI, vCenter, and ESX versions before running script.|`Boolean`       |
| `RevertToDefault` |`$false`                   |When specified the script will revert all settings back to the known default 'Out of the Box' values.|`Boolean`       |
| `GlobalVarsFile`  |`VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1`|Global Variables file name. Must be in the same directory as the script.|`String`       |
| `RemediationVarsFile`|`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1`|Remediation Variables file name. Must be in the same directory as the script.   |`String`       |

### Update environment specific variables
Update the `VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1` and `VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1` files with the target environment values for remediation. The file provided can be used or a copy can be made and updated.  

**NOTE** Update paths as needed for the environment.  

```
# Navigate to the PowerCLI hardening folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/

# Update the report path if needed, provide the vCenter server name, and for ESX remediation, specify a hostname or cluster. Order of precedence: hostname, cluster
vi VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1

# In this example a single ESX host named esx1.rainpole.local will be targeted
$ReportPath = "/tmp/reports"
$vcenter = "vcenter.rainpole.local"
$hostname = "esx1.rainpole.local"
$cluster = ""

# Update environment specific ESX variables
vi VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1

# Update any environment specific variables as needed. To disable/enable rules update the $rulesenabled section.
envstigsettings = [ordered]@{
  ntpServers              = @("time-a-g.nist.gov","time-b-g.nist.gov") # VCFE-9X-000121 Array of authorized NTP servers
  issueBanner             = @{"Config.Etc.issue" = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."} # VCFE-9X-000196
  lockdownExceptionUsers  = @() # VCFE-9X-000205 Note da-user,nsx-user,mux_user and the vcf-svc-* account user will be added for each host. Only add an environment specific users here.
  allowedips              = @("10.0.0.0/8","172.16.0.0/16") # VCFE-9X-000217 Allows IP ranges for the ESX firewall. Enter a comma separated list, for example: @("10.0.0.0/8","172.16.0.0/16")
  esxAdminsGroup          = "" # VCFE-9X-000239 Enter the environment specific AD group here if hosts are joined to AD and this capability is used.
}
```

### Run the remediation script

**⚠️ For rule VCFE-9X-000014 if it is needed to update the TLS profile the host must be in maintenance mode prior to running the script or this rule will be skipped. ** 

** ?? testing **

More...
[!WARNING]
This is critical stuff.

After remediation of VCFE-9X-000014 a reboot is required to complete the process.  

```
# Launch PowerShell
pwsh

# Create a PowerShell credential. The provided user must have administrative permissions to the target vCenter and vCenter SSO.
$vccred = Get-Credential

User: administrator@vsphere.local
Password for user administrator@vsphere.local: ********************

# Run the remediation script against the target ESX hosts
./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1 -vccred $vccred

# Snippet from the output of running the script.
[2025-05-14 14:46:40] [INFO] Importing Global Variables from: /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/./VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1
[2025-05-14 14:46:40] [INFO] Importing Remediation Variables from: /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1
[2025-05-14 14:46:40] [INFO] Starting Powershell Transcript at /tmp/reports/VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Transcript_5-14-2025_14-46-40.txt
Transcript started, output file is /tmp/reports/VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Transcript_5-14-2025_14-46-40.txt
[2025-05-14 14:46:40] [INFO] VMware vSphere ESX STIG Remediation - STIG Readiness Guide Version 1 Release 1
[2025-05-14 14:46:40] [EULA] Use of this tool constitutes acceptance of the license and terms of use found at:
[2025-05-14 14:46:40] [EULA] https://github.com/vmware/dod-compliance-and-automation
[2025-05-14 14:46:40] [INFO] Remediation of vcenter.rainpole.local started at 2025-05-14 14:46:40 from  by root
[2025-05-14 14:46:40] [SAFETY] This script requires PowerCLI 9.0.0 or newer. Current version is 9.0.0.24720632.
[2025-05-14 14:46:40] [INFO] Connecting to vCenter: vcenter.rainpole.local
[2025-05-14 14:47:23] [SAFETY] This script supports vCenter version 9.0.0 to 9.0.0. Current version is 9.0.0.
[2025-05-14 14:47:23] [INFO] Gathering info on target ESX hosts in vCenter: vcenter.rainpole.local
[2025-05-14 14:47:24] [INFO] Found target host: esx1.rainpole.local.
[2025-05-14 14:47:24] [SAFETY] This script supports ESX version 9.0.0 to 9.0.0. ESXi host: esx1.rainpole.local detected with version: 9.0.0.
[2025-05-14 14:47:24] [INFO] Remediating STIG ID: VCFE-9X-000005 with Title: The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user.
[2025-05-14 14:47:24] [CHANGED] Setting Security.AccountLockFailures was incorrectly set to 0 on Host: esx1.rainpole.local. Configuring value to 3.

Name                 Value                Type                 Description
----                 -----                ----                 -----------
Security.AccountLoc… 3                    VMHost

[2025-05-14 14:50:25] [INFO] Configuration Summary:
[2025-05-14 14:50:25] [INFO] {
  "vcenter": "vcenter.rainpole.local",
  "hostname": "esx1.rainpole.local",
  "cluster": "cluster0",
  "vmhosts": "esx1.rainpole.local",
  "reportpath": "/tmp/reports/",
  "ok": 41,
  "changed": 48,
  "skipped": 10,
  "failed": 3,

# A results file and PowerShell transcript is provided in the report path specified.
Directory: /tmp/reports

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---            5/14/2025  14:46 PM           6578 VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Results_5-14-2025_14-46-40.json
-a---            5/14/2025  14:46 PM          84552 VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Transcript_5-14-2025_14-46-40.txt

# Update global variables target and rerun script as needed
```

## Manually remediate rules
The following rules require manual remediation if not compliant and are not automated by the provided scripts.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFE-9X-000048`     |The ESX host must uniquely identify and must authenticate organizational users by using Active Directory.                               |
| `VCFE-9X-000138`     |The ESX host must enable bidirectional Challenge-Handshake Authentication Protocol (CHAP) authentication for Internet Small Computer Systems Interface (iSCSI) traffic.|
| `VCFE-9X-000202`     |The ESX host must configure a persistent log location for all locally stored logs and audit records.                                    |
| `VCFE-9X-000203`     |The ESX host must protect the confidentiality and integrity of transmitted information by isolating ESX management traffic.            |
| `VCFE-9X-000204`     |The ESX host must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic.           |
| `VCFE-9X-000215`     |The ESX host must disable Simple Network Management Protocol (SNMP) v1 and v2c.                                                         |
| `VCFE-9X-000232`     |The ESX host must not be configured to override virtual machine (VM) configurations.                                                     |
| `VCFE-9X-000233`     |The ESX host must not be configured to override virtual machine (VM) logger settings.                                                    |

## Functional Testing
Perform any needed functional testing to ensure the functionality and operation of the environment remain intact.

## Rerun auditing after remediation
To audit ESX hosts post-remediation rerun the auditing steps [here](/docs/tutorials/cloud-foundation-9.x/product/esx/audit9-esx/).