# Change Log

## [VCF 9.x STIG Readiness Guide] (2026-05-07)

#### Release Notes
- Release to support VCF 9.1.x

#### Roles Removed
- `ops_fm` - Removed role targeting VCF Operations Fleet Management appliance. Contained control VCFA-9X-000371. Component removed in VCF 9.1.
- `ops_fm_nginx` - Removed role targeting VCF Operations Fleet Management Nginx. Contained controls VCFQ-9X-000003, VCFQ-9X-000019, VCFQ-9X-000040, VCFQ-9X-000078, VCFQ-9X-000090, VCFQ-9X-000096, VCFQ-9X-000098. Component removed in VCF 9.1.
- `ops_logs` - Removed role targeting VCF Operations for Logs appliance. Contained controls VCFA-9X-000142, VCFA-9X-000143, VCFA-9X-000196, VCFA-9X-000253, VCFA-9X-000357, VCFA-9X-000358, VCFA-9X-000359, VCFA-9X-000360, VCFA-9X-000367. Component removed in VCF 9.1.
- `ops_logs_apache_tomcat` - Removed role targeting VCF Operations for Logs Apache Tomcat. Contained controls VCFT-9X-000001, VCFT-9X-000003, VCFT-9X-000005, VCFT-9X-000013, VCFT-9X-000014, VCFT-9X-000025, VCFT-9X-000036, VCFT-9X-000048, VCFT-9X-000057, VCFT-9X-000062, VCFT-9X-000065, VCFT-9X-000067, VCFT-9X-000070, VCFT-9X-000087, VCFT-9X-000122, VCFT-9X-000131, VCFT-9X-000132, VCFT-9X-000133, VCFT-9X-000134. Component removed in VCF 9.1.

#### Role Changes

**automation**
- Updated `automation_defaults_approved_feature_flags` default to include 'Fast Cross VC Instantiation Utilizing Shared Storage' and 'Enable OPS Notifications API'.

**nsx_manager**
- Expanded TLS cipher suite check and remediation to include six additional ciphers: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.

**nsx_routing**
- Added VCFR-9X-000028 - Disable NSX CEIP and telemetry schedule. New task file `nsx_routing_telemetry_conf.yml` and template `nsx_routing_update_telemetry_config.json.j2`.

**operations**
- Added VCFA-9X-000190 - Only allow the use of DOD PKI established certificate authorities (manual remediation).
- Added VCFA-9X-000196 - Require SSL connection (manual remediation).
- Removed VCFA-9X-000352 - Enable FIPS-validated cryptography (commented out, no longer applicable in VCF 9.1).
- Removed VCFA-9X-000365 - Forward VCF Operations Fleet Management logs to a central log server (removed along with Fleet Management component).
- Removed VCFA-9X-000366, VCFA-9X-000368, VCFA-9X-000369, VCFA-9X-000370 (removed, no longer applicable in VCF 9.1).

**ops_apache_httpd**
- Commented out VCFH-9X-000063 - Load http2_module (not applicable in current platform version).
- Commented out VCFH-9X-000094 - Configure Protocols h2/h2c directive (not applicable in current platform version).
- Removed VCFH-9X-000040, VCFH-9X-000063, VCFH-9X-000094 from tag index in main.yml.

**ops_net**
- Removed VCFA-9X-000378 - Enable FIPS-validated cryptography (no longer applicable in VCF 9.1).

**photon_5**
- Added PHTN-50-000266 to the auditd rules block tag list and `when` conditions.
- Added PHTN-50-000267 to the combined PAM system-auth remediation block (applied together with PHTN-50-000192 and PHTN-50-000206).
- Updated PHTN-50-000003 auditd handling to detect package version via `tdnf`; skips copying the audit rules template for auditd >= 3.0.9-25 to avoid duplicate rules from the built-in default.rules file.
- Added pre-check steps for idempotency on PHTN-50-000004 (deny, fail_interval), PHTN-50-000035 (ucredit), PHTN-50-000036 (lcredit), PHTN-50-000037 (dcredit), PHTN-50-000038 (difok), PHTN-50-000042 (PASS_MAX_DAYS), PHTN-50-000044 (minlen), PHTN-50-000086 (ocredit) — settings are only modified when out of compliance.
- Improved `regexp` patterns across multiple controls to use more precise anchored matching.
- Consolidated PHTN-50-000040 telnet removal into a single `tdnf remove` command.
- Added commented stubs for PHTN-50-000261, PHTN-50-000262, PHTN-50-000263, PHTN-50-000264, PHTN-50-000265, PHTN-50-000268, PHTN-50-000269 (present in codebase but disabled pending future enablement).

**sddcmgr**
- Corrected tag reference in main.yml from VCFA-9X-000365 to VCFA-9X-000364.

**ubuntu_2204**
- Role updated from Ubuntu 22.04 STIG to Ubuntu 24.04 STIG. All UBTU-22-xxxxxx control IDs replaced with UBTU-24-xxxxxx equivalents.
- Aligned with Canonical Ubuntu 24.04 LTS STIG V1R3/V1R4 (02 December 2025 / 05 January 2026).
- Increased total control count from 130 to 150 controls.
- Role metadata and galaxy tags updated to reflect ubuntu2404 target platform.

**vcenter_envoy**
- Added VCFK-9X-000075 - Configure rsyslog configuration file for Envoy.

---

## [VCF 9.x STIG Readiness Guide] (2025-06-17)

#### Release Notes
- Initial release to support VCF 9.0.0.0