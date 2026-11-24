# Change Log

## [9.x STIG Readiness Guide] (2026-11-24)

### Release Notes
- Updates to support VCF 9.1.2.0

#### ESX
- VCFE-9X-000205 - Added ft-user and lldpVim-user to the system accounts that are allowed to bypass lockdown mode
- VCFE-9X-000205 - Updated the approved user list and change counter to reset for each host so they do not carry over from the previous host
- VCFE-9X-000205 - Updated the lockdownExceptionUsers variable comment in the ESX remediation variables file to list the accounts added for each host
- VCFE-9X-000216 - Updated the revert to default workflow to use the correct defaultsettings variable name for the firewall default action
- VCFE-9X-000216 - Moved the rule so it follows the control order in the ESX remediation script
- VCFE-9X-000219, VCFE-9X-000220, VCFE-9X-000221 - Updated the skipped and error output to use Write-Message
- VMware_Cloud_Foundation_vSphere_ESX_9.X_STIG_InSpec_Runner.ps1 - Added the optional WaiverFile parameter to apply an InSpec waiver file during the audit

#### Virtual Machine
- VMware_Cloud_Foundation_vSphere_VM_9.X_STIG_InSpec_Runner.ps1 - Added the optional WaiverFile parameter to apply an InSpec waiver file during the audit


## [9.x STIG Readiness Guide] (2026-09-03)

### Release Notes
- Updates to support VCF 9.1.1.0


## [9.x STIG Readiness Guide] (2026-05-12)

### Release Notes
- Updates to support VCF 9.1.0


## [9.x STIG Readiness Guide] (Y25M09)

### Release Notes
- Updates to support VCF 9.0.1 and 9.0.2


## [9.x STIG Readiness Guide] (2025-06-17)

### Release Notes
- Initial release to support VCF 9.0.0.0
