# vmware-cloud-foundation-stig-powercli-hardening
VMware Cloud Foundation STIG Readiness Guide PowerCLI Scripts  
Updated: 2025-06-17  
STIG Release: Y25M06  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This repository represents a collection of Powershell/PowerCLI scripts that perform automated remediation STIG compliance for VMware Cloud Foundation. These scripts target vCenter, ESX, and virtual machine based rules.  

## Requirements
Minimum Versions
- VCF PowerCLI               : `9.0.0.0`
- VMware.VCF.STIG.Helpers    : `1.0.1`
- Powershell                 : `5.1`
- Powershell Core            : `7.3.4`

## Compatibility
- VCF 9.0.0.0  

## Support
- These profiles have not been tested for forward or backward compatibility beyond the version of VCF listed.  
- For more information on general STIG support, please see the [Support for Security Technical Implementation Guides](https://knowledge.broadcom.com/external/article?legacyId=94398) KB article.  

## VCF STIG Helpers Module
The VCF STIG Helpers module provides additional supporting functions to the scripts provided here and for the vSphere InSpec profiles.  

The functions provided are: `Set-vCenterCredentials` `Get-vCenterCredentials` `Set-PowerCLICredential` `Get-PowerCLICredentialUsername` `Get-PowerCLICredentialPassword` `Write-Message` `Write-Header` `Test-PowerCLI` `Test-vCenter` `Test-ESX`

Install the module by unzipping it into a supported module path depending on the target platform and location preference.  

## Included Scripts
`VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1` - Global variables used throughout all scripts.  
`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner_Attestations_Example.yml` - Example attestation file for the ESX InSpec runner script.  
`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner.ps1` - Audits target ESX hosts and facilitates creating accreditation artifacts that would require a more manual process with InSpec/CINC alone.  
`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1` - Variables specific to ESX remediation. Environment specific, rule enablement/disablement, expected stig values, default values for revert workflow.  
`VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1` - Remediation script for ESX.  
`VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Variables.ps1` - Variables specific to vCenter remediation. Environment specific, rule enablement/disablement, expected stig values, default values for revert workflow.  
`VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation.ps1` - Remediation script for vCenter.  
`VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_InSpec_Runner.ps1` - Audits target VMs and facilitates creating accreditation artifacts that would require a more manual process with InSpec/CINC alone.  
`VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Variables.ps1` - Variables specific to VM remediation. Environment specific, rule enablement/disablement, expected stig values, default values for revert workflow.  
`VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation.ps1` - Remediation script for VMs.  

## Running Remediation Scripts

### Prerequisites
Prior to running any scripts it is recommended to get familiar with the scripts and the required parameters as well as test them out in a non-production environment.  

Update the `VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1` file with the target environment values for remediation. The file provided can be used or a copy can be made an updated.  

**NOTE** Update paths as needed for the target environment environment.  

### Common Parameters
The follow parameters are available in all remediation scripts.  

|   Parameter Name  |       Default Value       |                                     Description                                |          Type         |
|-------------------|---------------------------|--------------------------------------------------------------------------------|-----------------------|
| `vccred`          |`None`                     |Powershell credential object for use in connecting to the target vCenter server.|`Powershell Credential`|
| `NoSafetyChecks`  |`$false`                   |Skip safety checks to verify PowerCLI, vCenter, and ESX versions before running script.|`Boolean`       |
| `RevertToDefault` |`$false`                   |When specified the script will revert all settings back to the known default 'Out of the Box' values.|`Boolean`       |
| `GlobalVarsFile`  |`VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1`|Global Variables file name. Must be in the same directory as the script.|`String`       |
| `RemediationVarsFile`|`varies`                |Remediation Variables file name. Must be in the same directory as the script.   |`String`       |

### Create Powershell credential
A Powershell credential is used to connect to vCenter instead of providing a username and password directly to the `Connect-VIServer` cmdlet.  

Create a Powershell credential. The provided user must have administrative permissions to the target vCenter and vCenter SSO.  
```
$vccred = Get-Credential
User: administrator@vsphere.local
Password for user administrator@vsphere.local: ********************
```

### ESX Remediation
Update the `VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1` file with the target environment values for remediation. The file provided can be used or a copy can be made an updated.  

Run the ESX remediation script with the provided variables files against the target ESX hosts specified in the global variables file.
```
./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1 -vccred $vccred
```

Run the ESX remediation script with the provided variables files against the target ESX hosts specified in the global variables file and disable safety checks.
```
./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1 -vccred $vccred -NoSafetyChecks
```

Run the ESX remediation script with custom variables files against the target ESX hosts specified in the global variables file.
```
./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1 -vccred $vccred -GlobalVarsFile "VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables_Custom_East.ps1" -RemediationVarsFile "VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables_Custom_East.ps1"
```

**NOTE** ESX hosts must be in maintenance mode to fully remediate them in order to change the TLS profile and require a reboot once hardened.  

### vCenter Remediation
Update the `VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation_Variables.ps1` file with the target environment values for remediation. The file provided can be used or a copy can be made an updated.  

Run the vCenter remediation script with the provided variables files against the target vCenter specified in the global variables file.
```
./VMware_Cloud_Foundation_vSphere_vCenter_9.0_STIG_Remediation.ps1 -vccred $vccred
```

### VM Remediation
Update the `VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation_Variables.ps1` file with the target environment values for remediation. The file provided can be used or a copy can be made an updated.  

Run the VM remediation script with the provided variables files against the target vCenter specified in the global variables file.
```
./VMware_Cloud_Foundation_vSphere_VM_9.0_STIG_Remediation.ps1 -vccred $vccred
```

### Disabling rules
The need may arise to disable certain rules for an environment. This can be accomplished in the remediation variables file for each script.  

For example to disable rule `VCFE-9X-000005` find the `$rulesenabled` section in the `VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation_Variables.ps1` file and update the value from `$true` to `$false` prior to running the script.
```
$rulesenabled = [ordered]@{
  VCFE9X000005 = $false  # Account Lock Failures
}
```
