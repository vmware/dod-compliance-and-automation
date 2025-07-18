# Remediate VCF Virtual Machines 9.0.0.0

## Overview
This tutorial covers remediating Virtual Machines in VCF deployments.  

> **Important** For the best experience, prior to using the STIG automation provided here please ensure you:  

> - Have familiarity with the rules contained in the various VMware STIGs and have evaluated those for impact and implementation considerations in the environment.  
> - Have an understanding of PowerShell and PowerCLI.
> - Have a back out plan so the changes can be rolled back if necessary.
> - Have read the [PowerCLI Overview](/docs/automation-tools/powercli/).

> **Failure to do so can result in unintended behavior in the environment.**  

The example commands below are specific to the product version and the supported STIG content for the version being run.

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

- `VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1` - Global variables used throughout all scripts.  
- `VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_InSpec_Runner.ps1` - Audits target VMs and facilitates creating accreditation artifacts that would require a more manual process with InSpec/CINC alone.  
- `VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Variables.ps1` - Variables specific to VM remediation. Environment specific, rule enablement/disablement, expected STIG values, default values for revert workflow.  
- `VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation.ps1` - Remediation script for VMs.  

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
| `RemediationVarsFile`|`VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Variables.ps1`|Remediation Variables file name. Must be in the same directory as the script.   |`String`       |

### Update environment specific variables
Update the `VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1` and `VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Variables.ps1` files with the target environment values for remediation. The file provided can be used or a copy can be made and updated.  

> **Note** Update paths as needed for the environment.  

```powershell
# Navigate to the PowerCLI hardening folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/

# Update the report path if needed, provide the vCenter server name, and for VM remediation, specify a vmname, cluster, or allvms. Order of precedence: vmname, cluster, allvms
vi VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1

# In this example all VMs in the vCenter specified will be targeted
$ReportPath = "/tmp/reports"
$vcenter = "vcenter.rainpole.local"
$cluster = ""
$vmname = ""
$allvms = $true

# Update environment specific VM variables
vi VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Variables.ps1

# Update any environment specific variables as needed. To disable/enable rules update the $rulesenabled section.
envstigsettings = [ordered]@{
  indDiskExceptions       = @("") # VCFV-9X-000213 Provide an array of VM names that are approved to have independent non-persistent disks present.
  floppyExceptions        = @("") # VCFV-9X-000214 Provide an array of VM names that are approved to have floppy drives present.
  cddvdExceptions         = @("") # VCFV-9X-000215 Provide an array of VM names that are approved to have CD/DVD drives connected.
  parallelExceptions      = @("") # VCFV-9X-000216 Provide an array of VM names that are approved to have parallel devices present.
  serialExceptions        = @("") # VCFV-9X-000217 Provide an array of VM names that are approved to have serial devices present.
  usbExceptions           = @("") # VCFV-9X-000218 Provide an array of VM names that are approved to have USB devices present.
  passthruExceptions      = @("") # VCFV-9X-000219 Provide an array of VM names that are approved to have passthrough DirectPath I/O devices present.
}
```

### Run the remediation script

```powershell
# Launch PowerShell
pwsh

# Create a PowerShell credential. The provided user must have administrative permissions to the target vCenter and vCenter SSO.
$vccred = Get-Credential

User: administrator@vsphere.local
Password for user administrator@vsphere.local: ********************

# Run the remediation script against the target ESX hosts
./VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation.ps1 -vccred $vccred

# Snippet from the output of running the script.
[2025-05-14 17:52:44] [INFO] Importing Global Variables from: /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1
[2025-05-14 17:52:44] [INFO] Importing Remediation Variables from: /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening/VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Variables.ps1
[2025-05-14 17:52:44] [INFO] Starting Powershell Transcript at /tmp/reports/VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Transcript_5-14-2025_17-52-44.txt
Transcript started, output file is /tmp/reports/VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Transcript_5-14-2025_17-52-44.txt
[2025-05-14 17:52:44] [INFO] VMware vSphere VM STIG Remediation - STIG Readiness Guide Version 1 Release 1
[2025-05-14 17:52:44] [EULA] Use of this tool constitutes acceptance of the license and terms of use found at:
[2025-05-14 17:52:44] [EULA] https://github.com/vmware/dod-compliance-and-automation
[2025-05-14 17:52:44] [INFO] Remediation of vcenter.rainpole.local started at 2025-05-14 17:52:44 from  by root
[2025-05-14 17:52:44] [SAFETY] This script requires PowerCLI 9.0.0 or newer. Current version is 9.0.0.24720632.
[2025-05-14 17:52:44] [INFO] Connecting to vCenter: vcenter.rainpole.local
[2025-05-14 17:52:52] [SAFETY] This script supports vCenter version 9.0.0 to 9.0.0. Current version is 9.0.0.
[2025-05-14 17:52:52] [INFO] Gathering info on target VMs in vCenter: vcenter.rainpole.local
[2025-05-14 17:52:53] [INFO] Found target VM: automation-qlbvq.
[2025-05-14 17:52:53] [INFO] Remediating STIG ID: VCFV-9X-000181 with Title: Virtual machines (VMs) must have copy operations disabled.
[2025-05-14 17:52:53] [PASS] Setting isolation.tools.copy.disable does not exist on VM: automation-qlbvq. The default value is compliant if the setting does not exist.
[2025-05-14 17:52:58] [INFO] Remediating STIG ID: VCFV-9X-000200 with Title: Virtual machines (VMs) must limit console sharing.
[2025-05-14 17:52:58] [CHANGED] Setting RemoteDisplay.maxConnections does not exist on VM: automation-qlbvq. Adding setting RemoteDisplay.maxConnections and configuring value to 1.

Name                 Value                Type                 Description
----                 -----                ----                 -----------
RemoteDisplay.maxCo… 1                    VM
[2025-05-14 17:53:51] [INFO] Configuration Summary:
[2025-05-14 17:53:51] [INFO] {
  "vcenter": "vcenter.rainpole.local",
  "cluster": "cluster1",
  "vms": [
    "automation-qlbvq"
  ],
  "allvms": true,
  "reportpath": "/tmp/reports",
  "ok": 647,
  "changed": 16,
  "skipped": 0,
  "failed": 0,

# A results file and PowerShell transcript is provided in the report path specified.
Directory: /tmp/reports

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---            5/14/2025  17:52 PM           6578 VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Results_5-14-2025_17-52-44.json
-a---            5/14/2025  17:52 PM          84552 VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Transcript_5-14-2025_17-52-44.txt

# Update global variables target and rerun script as needed
```

## Manually remediate rules
The following rules require manual remediation if not compliant and are not automated by the provided scripts or the VM must be powered off to perform the action.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFV-9X-000213`     |Virtual machines (VMs) must not use independent, nonpersistent disks.                                                                    |
| `VCFV-9X-000214`     |Virtual machines (VMs) must remove unneeded floppy devices.                                                                              |
| `VCFV-9X-000216`     |Virtual machines (VMs) must remove unneeded parallel devices.                                                                            |
| `VCFV-9X-000217`     |Virtual machines (VMs) must remove unneeded serial devices.                                                                              |
| `VCFV-9X-000218`     |Virtual machines (VMs) must remove unneeded USB devices.                                                                                 |
| `VCFV-9X-000219`     |Virtual machines (VMs) must disable DirectPath I/O devices when not required.                                                            |

## Functional Testing
Perform any needed functional testing to ensure the functionality and operation of the environment remain intact.

## Rerun auditing after remediation
To audit ESX hosts post-remediation rerun the auditing steps [here](/docs/tutorials/cloud-foundation-9.x/product/virtual-machines/audit9-vm/).
