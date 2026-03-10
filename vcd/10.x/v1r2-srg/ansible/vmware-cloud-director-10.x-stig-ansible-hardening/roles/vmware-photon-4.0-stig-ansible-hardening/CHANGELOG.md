# Change Log

## [4.0 Version 1 Release 5] (2024-01-04)

#### Release Notes
- PHTN-40-000047 removed bridge module from list to support container workloads
- PHTN-40-000231 updated task to not run if container host packages are installed
- PHTN-40-000247 new control to remove nullok from pam_unix.so module

## [4.0 Version 1 Release 4] (2023-08-08)

#### Release Notes
- Updated pwquality and pwhistory tasks to have the option of not using a conf file for configuration. Controlled with vars `var_pam_use_pwquality_conf` and `var_pam_use_pwhistory_conf`
- Updated handler notifications to include role name to avoid problems with handlers of the same name in other playbooks
- PHTN-40-000012 updated regex in task
- PHTN-40-000127 added libgcrypt to install command
- PHTN-40-000241 updated failed/change when conditions to work with earlier versions of Photon 4

## [4.0 Version 1 Release 3] (2023-06-06)

#### Release Notes
- PHTN-40-000012,26,43,74,111,121,161,222 updated fix
- PHTN-40-000067,105,241,242,243,244,245,246 new control
- PHTN-40-000083,202,230 removed
- PHTN-40-0000210 updated check
- Updated kernel parameter controls to use new conf file to address persistence across reboots and made idempotent if runtime config is compliant

## [4.0 Version 1 Release 2] (2023-04-26)

#### Release Notes
- Updated PHTN-40-000021 and 110 to match new content
- Lint fixes for newer version of ansible-lint
- Updated auditd STIG rules file
- Updated aide.conf template
- Fixed aide install task

## [4.0 Version 1 Release 1] (2022-07-12)

#### Release Notes
- Initial release for Photon 4.0