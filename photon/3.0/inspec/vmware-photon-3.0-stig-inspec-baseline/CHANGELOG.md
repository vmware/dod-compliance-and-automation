# Change Log

## [3.0 Version 1 Release 5] (2022-06-27)

#### Release Notes
- Additional style rubocop fixes
- Updated regex for PAM controls to validate more scenarios
-	PHTN-30-000053 was removed
-	PHTN-30-000077 was removed
-	PHTN-30-000245 was updated

## [3.0 Version 1 Release 4] (2022-04-18)

#### Release Notes
- Ran rubocop on profile to fix some linting issues
- PHTN-30-000026 Updated to OpenSSH version 7.4 or greater
- PHTN-30-000052 Removed in favor of 000005
- PHTN-30-000056 Added ROTATE as a valid value
- PHTN-30-000058 Added options for chrony and timesyncd
- PHTN-30-000094 Updated to not use eval criteria
- PHTN-30-000097 Updated test to verify folders exist
- PHTN-30-000240 Added Control
- PHTN-30-000245 Added Control

## [3.0 Version 1 Release 2] (2021-06-24)

#### Release Notes
- Updated control metadata with technical edits
- Added additional clarifying notes to auditd rule controls
- Added sysctl --load command to fix text for sysctl controls
- PHTN-30-000029 Added additional conditions for audit to pass
- PHTN-30-000032 Updated check finding language to include these options instead of exclusively
- PHTN-30-000034 Removed control
- PHTN-30-000049 Fixed typo in command causing it to return no results
- PHTN-30-000064 New control for sshd ciphers to cover cases fipsmode setting did not
- PHTN-30-000088 Updated value to 6 from 2 to help with authentication attempts for multiple methods unintentionally locking users out
- PHTN-30-000116 Removed control

#### Bug Fixes

## [3.0 Version 1 Release 1] (2020-04-20)

#### Release Notes
- Initial release for Photon 3.0