# Change Log

## [VCF 9.x STIG Readiness Guide] (2026-11-24)

### Release Notes
- Updates to support VCF 9.1.2.0

#### SDDC Manager NGINX
- Updated nginx.conf template to match the VCF 9.1.2.0 SDDC Manager configuration

#### Operations for Networks NGINX
- Updated nginx.conf template to remove the headers_more module load and the more_clear_headers directive. The module is not included in the VCF 9.1.2.0 appliance and NGINX fails to load the configuration with it
- Updated vnera_standalone template to match the VCF 9.1.2.0 Operations for Networks platform configuration
- Updated vnera_cluster_3_node template port 3100 listener headers to match the VCF 9.1.2.0 Content-Security-Policy and add the Permissions-Policy header

#### vCenter Appliance Envoy
- Updated vmware-services-rhttpproxy.conf template file

#### vCenter Appliance PostgreSQL
- VCFL-9X-000121 - Updated vmware-services-vmware-vpostgres.conf template file

#### vCenter Appliance VAMI
- VCFM-9X-000021 - Updated vmware-services-applmgmt.conf template file

#### Photon OS 5.0
- PHTN-50-000192, PHTN-50-000206, PHTN-50-000267 - Added an "Updated by Ansible" comment to /etc/pam.d/system-auth when the remediation changes the file

#### Ubuntu 22.04
- Aligned with Canonical Ubuntu 22.04 LTS STIG Version 2 Release 10

#### Ubuntu 24.04
- Aligned with Canonical Ubuntu 24.04 LTS STIG Version 1 Release 7
- playbook.yml - The Operations for Networks platform and proxy plays now apply the ubuntu_2404 role instead of ubuntu_2204, because the VCF 9.1.2.0 Operations for Networks appliances run Ubuntu 24.04
- group_vars/operations_networks_platform.yml, group_vars/operations_networks_proxy.yml - Replaced the Ubuntu 22.04 control overrides with the Ubuntu 24.04 equivalents


## [VCF 9.x STIG Readiness Guide] (2026-09-03)

### Release Notes
- Updates to support VCF 9.1.1.0


## [VCF 9.x STIG Readiness Guide] (2026-05-12)

### Release Notes
- Updates to support VCF 9.1.0


## [VCF 9.x STIG Readiness Guide] (Y25M09)

### Release Notes
- Updates to support VCF 9.0.1 and 9.0.2


## [VCF 9.x STIG Readiness Guide] (2025-06-17)

#### Release Notes
- Initial release to support VCF 9.0.0.0
