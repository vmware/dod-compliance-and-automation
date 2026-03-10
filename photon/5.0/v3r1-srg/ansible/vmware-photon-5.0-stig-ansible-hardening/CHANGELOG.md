# Change Log

## [5.0 Version 3 Release 1] (2025-06-17)

#### Release Notes
- Updated variable names and placement to conform with naming standards in VCF 9 Ansible playbook.
- Other misc task updates to match VCF 9 Ansible output improvements.
- Reduced logging output for aide tasks.

## [5.0 Version 2 Release 1] (2024-07-22)

#### Release Notes
- PHTN-50-000043 removed. Source requirement is no longer present in SRG.
- PHTN-50-000066 removed. Removed until all VCF appliances can support SELinux.
- PHTN-50-000085 updated.
- PHTN-50-000111 removed. Removed in favor of configuring syslog via the product interfaces(UI/API).
- PHTN-50-000121 removed. Removed in favor of configuring time sync via the product interfaces(UI/API).
- PHTN-50-000238 removed. Source requirement is no longer present in SRG.
- PHTN-50-000243 removed. Source requirement is no longer present in SRG.
- PHTN-50-000246 updated.

## [5.0 Version 1 Release 3] (2024-01-02)

#### Release Notes
- PHTN-50-000047 removed bridge module from list to support container workloads
- PHTN-50-000231 updated task to not run if container host packages are installed
- PHTN-50-000247 new control to remove nullok from pam_unix.so module

## [5.0 Version 1 Release 2] (2023-09-12)

### Release Notes
- Updated pwquality and pwhistory tasks to have the option of not using a conf file for configuration. Controlled with vars `var_pam_use_pwquality_conf` and `var_pam_use_pwhistory_conf`
- Updated handler notifications to include role name to avoid problems with handlers of the same name in other playbooks
- PHTN-50-000012 updated regex in task
- PHTN-50-000127 added libgcrypt to install command
- PHTN-50-000193,194,195,196 updated regex to find more incorrect configurations
- PHTN-50-000197 updated to not add duplicate pwquality.so line in some situations
- PHTN-50-000241 updated failed/change when conditions to work with earlier versions of Photon 4

## [5.0 Version 1 Release 1] (2023-05-31)

### Release Notes
- Initial release for Photon 5.0