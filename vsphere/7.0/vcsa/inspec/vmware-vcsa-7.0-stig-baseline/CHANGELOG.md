# Change Log

## [7.0 Official STIG Version 1 Release 2] (2023-07-26)

#### Release Notes
- Updated metadata to match official STIG V1R2
- VCEM-70-000008 updated test
- VCLU-70-000007 updated test
- PHTN-30-000019,41,54,61,62,94,97,108,109 updated test
- VCST-70-000006,28 updated test
- VCUI-70-000008 updated test
- VCLD-70-000007,14 updated test

## [7.0 Official STIG Version 1 Release 1] (2023-03-15)

#### Release Notes
- Updated metadata to match official STIG
- Photon is now included in this profile since the official vCenter Photon 3.0 STIG differs slightly from the Photon 3.0 STIG Readiness Guide

## [7.0 Version 1 Release 4] (2022-10-28)

#### Release Notes
- VCPG-70-000003 Updated group to reflect new group used for vPostgres
- VCPG-70-000005 Updated group to reflect new group used for vPostgres
- VCPG-70-000012 Updated group to reflect new group used for vPostgres
- PHTN-30-000039 Excluded in favor of configuring syslog in the VAMI
- PHTN-30-000058 Excluded in favor of configuring ntp in the VAMI
- VCPF-70-000017 Updated check to accommodate new service permission defaults
- VCUI-70-000007 Updated
- Misc typo fixes

## [7.0 Version 1 Release 3] (2022-04-29)

#### Release Notes
- Cookstyle lint corrections
- Profile now pulls Photon content from the Photon source repo instead of a copy here
- VCEM-70-000017 Updated owner and group, fixed issue a not properly spaced character in test
- VCLU-70-000007 Updated permissions to 640
- VCLU-70-000017 fixed issue a not properly spaced character in test
- VCPF-70-000017 fixed issue a not properly spaced character in test
- VCPF-70-000021 updated test to account for values on a separate line
- VCPF-70-000029 fix updated to match updates to log4j properties
- VCPG-70-000001 updated test to look for values in a range
- VCST-70-000008 Add .conf to grep statement
- VCUI-70-000005 Updated log pattern
- VCUI-70-000017 Updated owner and group, fixed issue a not properly spaced character in test
- VCLD-70-000002 updated fix restart command
- VCLD-70-000003 updated fix restart command
- VCLD-70-000019 fixed issue a not properly spaced character in test
- VCLD-70-000056 Added control

## [7.0 Version 1 Release 2] (2021-09-15)

#### Release Notes
- Content updates for check/fix text in various controls
- VCLU-70-000008 corrected command in test
- Excluded PHTN-30-000049 in the wrapper profile since it cannot be fixed in vCenter at this time.

## [7.0 Version 1 Release 1] (2021-03-05)

#### Release Notes
- Initial release
