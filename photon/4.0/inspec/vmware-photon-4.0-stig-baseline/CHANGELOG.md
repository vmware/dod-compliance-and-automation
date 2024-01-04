# Change Log

## [4.0 Version 1 Release 5] (2024-01-04)

#### Release Notes
- Misc. tech edits for PHTN-40-000003,07,19,31,35,36,37,38,41,43,46,67,68,76,78,86,105,160,173,175,184,185,187,193,196,200,204,206,213,214,215,216,223,224,225,226,227,228,229,232,238,244,246
- PHTN-40-000042 updated finding statement and test
- PHTN-40-000047 removed bridge module from list to support container workloads
- PHTN-40-000107 added /var/lib/docker path to exclude from check
- PHTN-40-000121 updated test to support ntp server input as an array instead of strings
- PHTN-40-000231 updated test to include input for container host systems to mark the control N/A
- PHTN-40-000247 new control

## [4.0 Version 1 Release 4] (2023-08-08)

#### Release Notes
- Updated source SRG to GPOS V2R6
- PHTN-40-000105,111 updated severity to match SRG
- PHTN-40-000005,47,49,59,79,130,160,193,199,239 misc. tech editing
- PHTN-40-000012 updated check command and test
- PHTN-40-000030 updated test to work when ran as non-root user
- PHTN-40-000035,36,37,38,44,86,184,235 updated tests for use cases when not using pwquality.conf file and updated note in check text
- PHTN-40-000043,243 updated tests for use cases when not using pwhistory.conf file. Removed order requirement for pam_pwhistory.so.
- PHTN-40-000059 updated test
- PHTN-40-000107 updated check to make it easier to assess this requirement
- PHTN-40-000192 updated test
- PHTN-40-000196 updated finding statements
- PHTN-40-000197 updated test
- PHTN-40-000206 updated test

## [4.0 Version 1 Release 3] (2023-06-06)

#### Release Notes
- PHTN-40-000012,26,43,74,111,121,161,222 updated check/fix
- PHTN-40-000030,79,93,127,130,239 updated test
- PHTN-40-000046 added note to fix
- PHTN-40-000067,105,241,242,243,244,245,246 new control
- PHTN-40-000083,202,230 removed
- PHTN-40-0000210 updated check
- Updated kernel parameter controls to use new conf file to address persistence across reboots
- Misc. tech edits to improve clarity of finding statements

## [4.0 Version 1 Release 2] (2023-04-26)

#### Release Notes
- Updated source SRG to GPOS V2R5
- Added rid/gid metadata
- Misc. tech edits
- Misc. test improvements to pass inspec check
- PHTN-40-000007,13,39,46,92,110,111,112,130,188,199,207,208,239 severity updated
- PHTN-40-000021 updated check/fix
- PHTN-40-000107 updated check
- PHTN-40-000110 updated check/fix
- updated aide.conf template

## [4.0 Version 1 Release 1] (2022-07-12)

#### Release Notes
- Initial release for Photon 4.0