# Change Log

## [VCF 9.x PowerCLI Hardening] (2026-11-20)

### Bug Fixes
- Fixed `VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_Remediation.ps1`: replaced calls to undefined functions `Write-ToConsoleBlue` and `Write-ToConsoleRed` with `Write-Message` from the VMware.VCF.STIG.Helpers module. The calls were in the disabled-control and failure handling and caused a "term is not recognized" error when a control was disabled or failed.
