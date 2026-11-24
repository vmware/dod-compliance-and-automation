# Change Log

## [Version 1 Release 7] (2026-10-05)

#### Release Notes
- UBTU-24-100050 - Removed nfs-common from Check and Fix; now only checks the nfs-kernel-server package. Updated test.
- UBTU-24-101100 - Added new control. Added requirement to ensure the OS does not assign an interactive login shell for system accounts.
- UBTU-24-200270 - Updated Fix to use "/etc/audit/rules.d/stig.rules".
- UBTU-24-200680 - Removed.
- UBTU-24-300019 - Updated Check command.
- UBTU-24-400310 - Updated maximum password lifetime from 60 to 180 days in title, check, fix and test. Updated CCI and NIST tags; removed satisfies tag.
- UBTU-24-600090 - Updated severity from medium to high.
- UBTU-24-700020 - Updated Check and Fix; journal directories now allow permissions up to 2755. Updated test.
- UBTU-24-700060, UBTU-24-700080, UBTU-24-700090 - Updated Fix tmpfiles.d configuration.
- UBTU-24-900315 - Added new control. Added requirement to audit the useradd command.
- UBTU-24-909000 - Updated Check and Fix to verify the audit system is running immutable ("enabled 2") and "-e 2" is set in "/etc/audit/rules.d/". Updated test; removed audit_rules_file input.
- UBTU-24-909890 - Updated Check and Fix to use AIDE sub-configuration directory and both "/usr/sbin" and "/sbin" paths. Updated test.
- Requirements were updated throughout to reflect the change from DOD to DoW.

## [Version 1 Release 6] (2026-07-01)

#### Release Notes
- UBTU-24-300022, UBTU-24-300023, UBTU-24-300031, UBTU-24-600010 - Updated Fix Text SSH restart command.
- UBTU-24-300028 - Added /etc/pam.d/common-auth to Fix Text.


## [Version 1 Release 5] (2026-04-01)

#### Release Notes
- UBTU-24-300025 - Updated Fix to explicitly specify array of strings data type for gsettings logout key; updated Check command output.
- UBTU-24-700020, UBTU-24-700060, UBTU-24-700070, UBTU-24-700080, UBTU-24-700090 - Updated permissions to align with Canonical recommendations.


## [Version 1 Release 4] (2026-01-05)

#### Release Notes
- UBTU-24-100050 - Added control.
- UBTU-24-100110 - Updated Title.
- UBTU-24-100860 - Updated check text.
- UBTU-24-102010 - Updated check and fix text. Update test.
- UBTU-24-200270 - Updated check text.
- UBTU-24-300024 - Removed control.
- UBTU-24-400340 - Updated check and fix text. Update test.
- UBTU-24-600070 - Updated check text.
- UBTU-24-700400 - Updated check and fix text. Update test.


## [Version 1 Release 3] (2025-12-02)

#### Release Notes
- Rule numbers updated throughout due to changes in the content management system.
- UBTU-24-100110 - Updated check text. Update test.
- UBTU-24-100840 - Updated check text.
- UBTU-24-200090 - Updated check text.
- UBTU-24-300028 - Updated check and fix text. Update test.
- UBTU-24-300039 - Updated check text and fix text.
- UBTU-24-700010 - Updated check and fix text. Update test.
- UBTU-24-700400 - Updated check and fix text. Update test.
- UBTU-24-901230 - Updated check text and fix text.
- UBTU-24-901240 - Updated check text and fix text.
- UBTU-24-901250 - Updated check text and fix text.
- UBTU-24-909890 - Updated check and fix text. Update test. Updated STIGID from UBTU-24-90890.


## [Version 1 Release 2] (2025-07-02)

#### Release Notes
- Initial release
- UBTU-24-200000 - Updated check text.
- UBTU-24-200020 - Updated fix text.
- UBTU-24-200040 - Updated check and fix text. Update test.
- UBTU-24-200041 - Added control.
- UBTU-24-200042 - Added control.
- UBTU-24-200043 - Added control.
- UBTU-24-200270 - Added control.
- UBTU-24-300006 - Updated check and fix text. Update test.
- UBTU-24-300007 - Updated check and fix text. Update test.
- UBTU-24-300008 - Updated check and fix text. Update test.
- UBTU-24-300009 - Updated check and fix text. Update test.
- UBTU-24-300019 - Added control.
- UBTU-24-300020 - Added control.
- UBTU-24-300021 - Updated check and fix text. Update test.
- UBTU-24-300025 - Updated check and fix text. Update test.
- UBTU-24-400220 - Updated check and fix text. Update test.
- UBTU-24-600070 - Updated check and fix text. Update test.


## [Version 1 Release 1] (2025-01-28)

#### Release Notes
- Initial release
