| [![Lint InSpec on Pushes.](https://github-vcf.devops.broadcom.net/vcf/canonical-ubuntu-24.04-lts-stig-baseline/actions/workflows/lint-inspec-on-push.yml/badge.svg?branch=main)](https://github-vcf.devops.broadcom.net/vcf/canonical-ubuntu-24.04-lts-stig-baseline/actions/workflows/lint-inspec-on-push.yml) | Main | [![Lint InSpec on Pushes.](https://github-vcf.devops.broadcom.net/vcf/canonical-ubuntu-24.04-lts-stig-baseline/actions/workflows/lint-inspec-on-push.yml/badge.svg?branch=development)](https://github-vcf.devops.broadcom.net/vcf/canonical-ubuntu-24.04-lts-stig-baseline/actions/workflows/lint-inspec-on-push.yml) | Development |
|:-|:-|:-|:-|
# canonical_ubuntu_24.04_lts_stig_baseline
Canonical Ubuntu 24.04 LTS STIG Chef InSpec Profile  
Version: Version 1 Release 5  
Date: 01 April 2026  
STIG Type: Official STIG  
Maintainers: Broadcom   

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the Canonical Ubuntu 24.04 LTS STIG.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor (Recommended)](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target system or can be run against the local system. 
- Root or sudo access to the target system
- Update the inputs in inspec-example.yml or make a new copy and update as appropriate for your environment

## Inputs
Inputs are used to provide variable information that customize how the profile is ran against the target system. Below is a list of inputs available for this profile that can be provided.  

|              Input Name              |                                           Default Value                                       |                                                      Description                                                      |   Type   |                                                         STIG IDs                                                         |
|--------------------------------------|-----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|----------|--------------------------------------------------------------------------------------------------------------------------|
|aide_conf_path                        |/etc/aide/aide.conf                                                                            |Path to aide.conf.                                                                                                     |String    |UBTU-24-90890                                                                                                             |
|audisp_remote_config_file             |/etc/audit/plugins.d/au-remote.conf                                                            |Audisp remote Configuration file.                                                                                      |String    |UBTU-24-100450                                                                                                            |
|audit_sp_remote_server                |Empty                                                                                          |Address of the remote syslog server to receive audit logs.                                                             |String    |UBTU-24-100450                                                                                                            |
|sshdcommand                           |`sshd -T`                                                                                      |If a different sshd command is needed then supply a different input value such as if there are user matching rules.    |String    |All SSHD Rules                                                                                                            |
|maxlogins                             |10                                                                                             |Maximum number of concurrent sessions in limits.conf.                                                                  |Numeric   |UBTU-24-200000                                                                                                            |
|tmout                                 |600                                                                                            |Inactivity timeouts, in seconds, after which operating system automatically terminates a user session. >0 and <=600.   |Numeric   |UBTU-24-200060                                                                                                            |
|temporary_accounts                    |[]                                                                                             |Temporary user account list.                                                                                           |Array     |UBTU-24-200250                                                                                                            |
|useradd_configuration                 |/etc/default/useradd                                                                           |Specifies default settings applied when creating new user accounts using the `useradd` command on Linux systems.       |String    |UBTU-24-200260                                                                                                            |
|approved_system_groups                |'root','daemon','amd','shadow','mail','crontab', '_ssh'                                        |List of approved group owners for system command files.                                                                |Array     |UBTU-24-300013                                                                                                            |
|password_quality_file                 |/etc/security/pwquality.conf                                                                   |File to configure password quality policies.                                                                           |String    |UBTU-24-300014,UBTU-24-300016,UBTU-24-400260,UBTU-24-400270,UBTU-24-400280,UBTU-24-400290,UBTU-24-400320,UBTU-24-400330   |
|common_password_file                  |/etc/pam.d/common-password                                                                     |File to configure password-related policies.                                                                           |String    |UBTU-24-300016,UBTU-24-300028,UBTU-24-400220                                                                              |
|common_auth_file                      |/etc/pam.d/common-auth                                                                         |File to configure authentication rules.                                                                                |String    |UBTU-24-200610,UBTU-24-300017,UBTU-24-300028,UBTU-24-400020                                                                              |
|faillock_file                         |/etc/security/faillock.conf                                                                    |File to define how the system responds to failed authentication attempts.                                              |String    |UBTU-24-200610                                                                                                            |
|pam_pkcs11_config_file                |/etc/pam_pkcs11/pam_pkcs11.conf                                                                |Configuration file for the pam_pkcs11.so PAM module                                                                    |String    |UBTU-24-400060,UBTU-24-400375,UBTU-24-400380                                                                              |
|sssd_conf_d_directory                 |/etc/sssd/conf.d                                                                               |Path to sssd conf.d directory                                                                                                  |String    |UBTU-24-400340                                                                                             |
|sssd_conf_path                        |/etc/sssd/sssd.conf                                                                            |Path to sssd.conf.                                                                                                     |String    |UBTU-24-400340,UBTU-24-400360,UBTU-24-400370                                                                              |
|smartcards_used                       |false                                                                                          |If smartcards are used for local logins.For VMware appliance this is false by default.                                 |Boolean	  |UBTU-24-400340,UBTU-24-400360                                                                                             |
|fips_config_file                      |/proc/sys/crypto/fips_enabled                                                                  |Path to enable FIPS.                                                                                                   |String    |UBTU-24-600030                                                                                                            |
|is_kdump_required                     |false                                                                                          |Is kdump service required? (check with SA and documented with ISSO)                                                    |Boolean   |UBTU-24-600070                                                                                                            |
|sudo_accounts                         |[]                                                                                             |Array of users who need access to security functions are part of the sudo group.                                       |Array     |UBTU-24-600130                                                                                                            |
|is_system_networked                   |true                                                                                           |Set to true if the system is networked for NTP check.                                                                  |Boolean   |UBTU-24-600160                                                                                                            |
|chrony_conf_file_path                 |/etc/chrony/chrony.conf                                                                        |Path to chrony conf file.                                                                                              |String    |UBTU-24-600160,UBTU-24-600180                                                                                             |
|approved_wireless_network_interfaces  |[]                                                                                             |Array of approved network interfaces (wired & wireless).                                                               |Array     |UBTU-24-600230                                                                                                            |
|minimum_accepted_partition_size       |8894028                                                                                        |Set audit log size in bytes (default:1073741824 per control specification).                                            |Numeric   |UBTU-24-900920                                                                                                            |
|audit_offload_script_name             |Empty                                                                                          |Script file name for audit offload in cron.weekly.                                                                     |String    |UBTU-24-900950                                                                                                            |
|action_mail_acct                      |root                                                                                           |Email to be notified when allocated audit record storage volume reaches capacity.                                      |String    |UBTU-24-900960,UBTU-24-900980                                                                                             |
|audit_tools                           |'/sbin/auditctl','/sbin/aureport','/sbin/ausearch','/sbin/autrace','/sbin/auditd','/sbin/augenrules'  |Array of audit tools to check ownership and permissions.                                                        |Array     |UBTU-24-901230,UBTU-24-901240,UBTU-24-901250                                                                              |
|audit_rules_file                      |/etc/audit/audit.rules                                                                         |File to configure audit rules.                                                                                         |String    |UBTU-24-909000                                                                                                            |


## Running the profile

#### Run all controls in the profile against a target node with an SSH Key
```
cinc-auditor exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --sudo --show-progress
```

#### Run all controls in the profile against a target node with a password
```
cinc-auditor exec <Profile> -t ssh://USER@IPorFQDN --password '<password>' --sudo --show-progress
```

#### Run all controls in the profile against a target node and output results to JSON
```
cinc-auditor exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --sudo --show-progress --reporter cli json:/tmp/results.json
```

#### Run a subset or a single control in the profile against a target node 
```
cinc-auditor exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --sudo --show-progress --controls=<control id>
```

#### Run all controls in the profile against a target node and specify a waiver file 
```
cinc-auditor exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --sudo --show-progress --waiver-file <waiverfile.yml>
```

**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.  
**Note**: inspec and cinc-auditor commands can be used interchangeably  

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into [MITRE's Heimdall](https://github.com/mitre/heimdall2) server for a more polished visual result.

## InSpec Vendoring
When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with `inspec vendor --overwrite`
