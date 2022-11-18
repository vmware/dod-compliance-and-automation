# Change Log

## [7.0 Version 1 Release 4] (2022-10-28)

#### Release Notes
- VCPG-70-000003 Updated group to reflect new group used for vPostgres
- VCPG-70-000005 Updated group to reflect new group used for vPostgres
- VCPG-70-000012 Updated group to reflect new group used for vPostgres
- PHTN-30-000039 Excluded in favor of configuring syslog in the VAMI
- PHTN-30-000058 Excluded in favor of configuring ntp in the VAMI
- VCPF-70-000017 Updated check to accomodate new service permission defaults
- VCUI-70-000007 Updated
- Misc typo fixes

## [7.0 Version 1 Release 3] (2022-04-29)

#### Release Notes
- Ansible lint corrections
- Profile now pulls Photon content from the Photon source repo instead of a copy here
- Reworked PostgreSQL tasks to not edit config file and instead set values through psql
- VCEM-70-000017 Updated owner and group
- VCLU-70-000007 Updated permissions to 640
- VCPF-70-000029 fix updated to match updates to log4j properties
- VCUI-70-000005 Updated log pattern
- VCUI-70-000017 Updated owner and group
- VCLD-70-000056 Added control

#### Known Issues
- Some versions of vCenter may ship with "FipsMode yes" twice in the sshd_config. When the playbook adds the ciphers option this may cause sshd to not start because it requires the ciphers option to be after FipsMode.

## [7.0 Version 1 Release 2] (2021-09-15)

#### Release Notes
- Content updates for check/fix text in various controls

## [7.0 Version 1 Release 1] (2021-03-05)

#### Release Notes
- Initial release
