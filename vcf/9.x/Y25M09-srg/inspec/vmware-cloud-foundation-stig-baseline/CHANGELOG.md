# Change Log

## [9.x STIG Readiness Guide] (Y26M05) - Updated July 2026

#### Checklist Generation / Metadata
- Corrected InSpec profile `name` fields to match the required machine-readable slug (was incorrectly set to the display title in some profiles, breaking `saf convert hdf2ckl` metadata matching)
- Migrated version numbering in inspec.yml files to Version.Release.Patch scheme (previously Version.Patch.Release), fixing STIG Viewer's Version/Release display
- Corrected/added `saf_cli_hdf2ckl_metadata.json` file so checklist generation reflects the right profile version, release, and date
- Fixed ESX PowerCLI runner script's management IP/MAC lookup (`Get-VMHostNetworkAdapter` failed against hosts using VCF's integrated networking; replaced with a direct `ExtensionData` read)
- ESX/VM PowerCLI runner scripts now generate checklist metadata via a per-host file (`-m`) instead of individual CLI flags, which SAF CLI was silently ignoring (specifically release date)

## [9.x STIG Readiness Guide] (Y25M09)

### Release Notes
- Updates to support VCF 9.0.1 and 9.0.2

#### ESX
- VCFE-9X-000082 - Updated Check
- VCFE-9X-000108 - Updated Check
- VCFE-9X-000130 - Updated Severity
- VCFE-9X-000203 - Updated Test

## [9.x STIG Readiness Guide] (Y25M06)

#### Release Notes
- Initial release to support VCF 9.0.0.0
