# Change Log

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