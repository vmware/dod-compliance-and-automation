# Change Log

## [VCF 9.x STIG Readiness Guide] (Y25M09) - Updated July 2026

#### Checklist Generation / Metadata
- Corrected InSpec profile `name` fields to match the required machine-readable slug (was incorrectly set to the display title in some profiles, breaking `saf convert hdf2ckl` metadata matching)
- Migrated version numbering in inspec.yml files to Version.Release.Patch scheme (previously Version.Patch.Release), fixing STIG Viewer's Version/Release display
- Corrected/added `saf_cli_hdf2ckl_metadata.json` files so checklist generation reflects the right profile version, release, and date

## [VCF 9.x STIG Readiness Guide] (Y25M09)

### Release Notes
- Updates to support VCF 9.0.1 and 9.0.2

#### Envoy
- Updated source DISA SRG to the Web Server Security Requirements Guide V4R4
- Updated vmware-services-envoy.conf template file
- VCFK-9X-000075 - config file changes

#### PostgreSQL
- Updated source DISA SRG to the Database Security Requirements Guide V4R4
- Updated vmware-services-vmware-postgres-archiver.conf template file
- Updated vmware-services-vmware-vpostgres.conf template file
- VCFL-9X-000121 - config file changes

#### VAMI
- VCFM-9X-000021 - config file changes

## [VCF 9.x STIG Readiness Guide] (Y25M06)

#### Release Notes
- Initial release to support VCF 9.0.0.0
