# Change Log

## [3.0 Version 1 Release 5] (2022-06-27)

#### Release Notes
- Updated backup steps to not fail if file doesn't exist and to not be displayed as a change
- Misc improvements
- PHTN-30-000053 Removed
- PHTN-30-000077 Removed

## [3.0 Version 1 Release 4] (2022-04-18)

#### Release Notes
- Ansible-lint syntax fixes
- Moved backup files to /tmp/ansible-backups-{date} since some files when backed up to the same folder as the original cause issues
- PHTN-30-000052 Removed in favor of 000005
- PHTN-30-000056 Added ROTATE as a valid value
- PHTN-30-000240 Added Control
- PHTN-30-000245 Added Control

## [3.0 Version 1 Release 2] (2021-06-24)

#### Release Notes
- Added backup procedure for all files updated or changed. Can be turned off in the defaults main.yml.
- PHTN-30-000034 Removed control
- PHTN-30-000064 New control for sshd ciphers to cover cases fipsmode setting did not
- PHTN-30-000088 Updated value to 6 from 2 to help with authentication attempts for multiple methods unintentionally locking users out
- PHTN-30-000116 Removed control

#### Bug Fixes
- Added variables for files referenced in tasks
- Cleaned up defaults main.yml file
- Added changelog file
- Updated readme

## [3.0 Version 1 Release 1] (2020-04-20)

#### Release Notes
- Initial release for Photon 3.0