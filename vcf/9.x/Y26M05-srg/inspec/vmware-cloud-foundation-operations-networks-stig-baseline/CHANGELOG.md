# Change Log

## [VCF 9.x STIG Readiness Guide] (Y26M05) - Updated July 2026

#### Checklist Generation / Metadata
- Corrected InSpec profile `name` fields to match the required machine-readable slug (was incorrectly set to the display title in some profiles, breaking `saf convert hdf2ckl` metadata matching)
- Migrated version numbering in inspec.yml files to Version.Release.Patch scheme (previously Version.Patch.Release), fixing STIG Viewer's Version/Release display
- Corrected/added `saf_cli_hdf2ckl_metadata.json` files so checklist generation reflects the right profile version, release, and date

## [VCF 9.x STIG Readiness Guide] (Y26M05)

### Release Notes
- Updates to support VCF 9.1

## [VCF 9.x STIG Readiness Guide] (Y25M09)

### Release Notes
- Updates to support VCF 9.0.1 and 9.0.2

#### NGINX
- Updated source DISA SRG to the Web Server Security Requirements Guide V4R4
- VCFO-9X-000004 - Updated Fix
- VCFO-9X-000103 - Updated Fix
- VCFO-9X-000104 - Updated Fix
- VCFO-9X-000105 - Updated Fix
- VCFO-9X-000106 - Updated Fix
- VCFO-9X-000137 - Updated InSpec

## [VCF 9.x STIG Readiness Guide] (Y25M06)

#### Release Notes
- Initial release to support VCF 9.0.0.0
