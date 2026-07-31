# Change Log

## [VCF 9.x STIG Readiness Guide] (Y26M05) - Updated July 2026

#### Checklist Generation / Metadata
- Corrected InSpec profile `name` fields to match the required machine-readable slug (was incorrectly set to the display title in some profiles, breaking `saf convert hdf2ckl` metadata matching)
- Migrated version numbering in inspec.yml files to Version.Release.Patch scheme (previously Version.Patch.Release), fixing STIG Viewer's Version/Release display
- Corrected/added `saf_cli_hdf2ckl_metadata.json` files so checklist generation reflects the right profile version, release, and date

## [VCF 9.x STIG Readiness Guide] (Y26M05)

### Release Notes
- Updates to support VCF 9.1

#### NGINX
- Updated source DISA SRG to the Web Server Security Requirements Guide V4R4
- VCFB-9X-000001 - Updated InSpec 
- VCFB-9X-000026 - Updated Check 

#### PostgreSQL
- Updated source DISA SRG to the Database Security Requirements Guide V4R4
- VCFC-9X-000001 - Updated Check and Fix
- VCFC-9X-000005 - Updated Check
- VCFC-9X-000007 - Updated Check and Fix
- VCFC-9X-000009 - Updated Check and Fix
- VCFC-9X-000010 - Updated Check and Fix
- VCFC-9X-000020 - Updated Check and Fix
- VCFC-9X-000032 - Updated Check and Fix
- VCFC-9X-000035 - Updated Check and Fix
- VCFC-9X-000038 - Updated Check and Fix
- VCFC-9X-000051 - Updated Check and Fix
- VCFC-9X-000060 - Updated Check and Fix
- VCFC-9X-000073 - Updated Check and Fix
- VCFC-9X-000109 - Updated Check and Fix
- VCFC-9X-000113 - Updated Check and Fix
- VCFC-9X-000144 - Updated Check and Fix

## [VCF 9.x STIG Readiness Guide] (Y25M06)

#### Release Notes
- Initial release to support VCF 9.0.0.0
