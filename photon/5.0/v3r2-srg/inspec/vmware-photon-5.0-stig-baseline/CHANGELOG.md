# Change Log

## [5.0 Version 3 Release 2] (2025-10-01)

#### Release Notes
- PHTN-50-000192 updated check and fix text as well as the test.
- PHTN-50-000203 updated check and fix text as well as the test.
- PHTN-50-000206 updated check text and test.
- PHTN-50-000219 updated check and fix text as well as the test.
- PHTN-50-000231 updated check text.
- PHTN-50-000245 updated control
- PHTN-50-000261 new control
- PHTN-50-000262 new control
- PHTN-50-000263 new control
- PHTN-50-000264 new control
- PHTN-50-000265 new control
- PHTN-50-000266 new control
- PHTN-50-000267 new control
- PHTN-50-000268 new control
- PHTN-50-000269 new control

## [5.0 Version 3 Release 1] (2025-06-17)

#### Release Notes
- Updated source SRG to the GPOS SRG V3R2.
- Updated rule applicability for VCF 9.0.0.0 Photon 5 based appliances.
- PHTN-50-000012 updated check text.
- PHTN-50-000074 updated check text.
- PHTN-50-000133 updated check text and test.
- PHTN-50-000231 updated check text.
- PHTN-50-000241 updated check text.
- PHTN-50-000242 updated check text.
- PHTN-50-000245 updated check text.

## [5.0 Version 2 Release 1] (2024-07-22)

#### Release Notes
- Updated source SRG to the GPOS SRG V3R1 which is now based on NIST 800-53 rev5
- PHTN-50-000043 removed. Source requirement is no longer present in SRG.
- PHTN-50-000066 removed. Removed until all VCF appliances can support SELinux.
- PHTN-50-000085 updated check and fix text as well as the test.
- PHTN-50-000111 removed. Removed in favor of configuring syslog via the product interfaces(UI/API).
- PHTN-50-000121 removed. Removed in favor of configuring time sync via the product interfaces(UI/API).
- PHTN-50-000206 updated check text note.
- PHTN-50-000238 removed. Source requirement is no longer present in SRG.
- PHTN-50-000243 removed. Source requirement is no longer present in SRG.
- PHTN-50-000246 updated check and fix text as well as the test.

## [5.0 Version 1 Release 3] (2024-01-02)

#### Release Notes
- PHTN-50-000042 updated finding statement and test
- PHTN-50-000047 removed bridge module from list to support container workloads
- PHTN-50-000107 added /var/lib/docker path to exclude from check
- PHTN-50-000121 updated test to support ntp server input as an array instead of strings
- PHTN-50-000231 updated test to include input for container host systems to mark the control N/A
- PHTN-50-000247 new control

## [5.0 Version 1 Release 2] (2023-09-15)

#### Release Notes
- Updated source SRG to GPOS V2R6
- PHTN-50-000105,111 updated severity to match SRG
- PHTN-50-000003,5,7,19,31,41,42,43,46,47,49,59,66,76,78,79,130,160,173,175,185,187,193,199,204,206,223,239,241 misc. tech editing
- PHTN-50-000012 updated check command and test
- PHTN-50-000030 updated test to work when ran as non-root user
- PHTN-50-000035,36,37,38,44,86,184,235 updated tests for use cases when not using pwquality.conf file and updated note in check text
- PHTN-50-000043,243 updated tests for use cases when not using pwhistory.conf file. Removed order requirement for pam_pwhistory.so.
- PHTN-50-000059 updated test
- PHTN-50-000067,68,105,160,223,224,225,226,227.228,229,231,232,244,246 updated sysctl load command in fix
- PHTN-50-000107 updated check to make it easier to assess this requirement
- PHTN-50-000192 updated test
- PHTN-50-000196 updated finding statements
- PHTN-50-000197 updated test
- PHTN-50-000206 updated test

## [5.0 Version 1 Release 1] (2023-05-31)

#### Release Notes
- Initial release for Photon 5.0