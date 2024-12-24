# jammy-compliance-release

<a name="warning">:warning:  The `jammy-compliance-release` is not compatible with `auditd` job
in [os-conf-release](https://github.com/cloudfoundry/os-conf-release)</a>

## CIS

The `cis` job is intended to be used to change stemcell configuration to pass the Jammy CIS rules. Below is a list of
variables that can be set in the [runtime-config](./runtime-config-cis.yml) for configurations based on your deployment
compliance requirements.

| variable                     | description                                                                                                                                                                                                                          | default |
|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `set_password_max_days`      | set `PASS_MAX_DAYS` in `/etc/login.defs`                                                                                                                                                                                             | `false` |
| `password_max_days`          | Applicable if `set_password_max_days` is set to `true`. If set, passwords will expire once they reach max days.                                                                                                                      | `30`    |
| `set_useradd_inactive`       | set `INACTIVE` value for `useradd`                                                                                                                                                                                                   | `false` |
| `useradd_inactive`           | Applicable if `set_useradd_inactive` is set to `true`. If set, user accounts that have been inactive for over a given period of time can be automatically disabled.                                                                  | `30`    |
| `set_user_shell_timeout`     | set default user shell timeout                                                                                                                                                                                                       | `false` |
| `user_shell_timeout`         | Applicable if `set_useradd_inactive` is set to `true`. User shell timeout in seconds                                                                                                                                                 | `900`   |
| `restirct_su`                | If set to `true`,  `group` key for `pam_wheel.so` statement in `/etc/pam.d/su` will be set to a group with no users. This group is intentionally empty to reinforce the use of `sudo` instead of `su` for privileged access.         | `false` |
| `make_audit_rules_immutable` | If set to `true`, this job will make audit rules immutable. Any change to auditd rules will require a reboot. Also see :warning: [warning](#warning) above. `auditd` job in `os-conf-release` also sets audit rules to be immutable. | `false` |

### usage

- `bosh cr && bosh ur`
- Edit the release version and variables in the [runtime-config-cis](runtime-config-cis.yml)
- `bosh urc --name cis-compliance runtime-config-cis.yml`
- `Apply Changes`

## STIG

The `stig` is intended to be used to change the stemcell configurations to
pass [Jammy Version 1, Revision 1](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V1R1_STIG.zip)
rules.

| Rule Number | Severity | Description                                                                                                                                                                                                                                                                                                  |
|-------------|:---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| V-238309    | Medium   | The Ubuntu operating system must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access.                                                                                                                                                  |
| V-260476    | Low      | Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) prevents the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization. |
| V-260477    | Medium   | Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed.                                                                                                                                                       |
| V-260490    | Medium   | Ubuntu 22.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.                                                                                                                                                                                  |
| V-260512    | Medium   | Ubuntu 22.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users.                                                                                                                                                                                                |
| V-260530    | Medium   | Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.                                                                                                                                                                                                                  |
| V-260531    | Medium   | Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.                                                                                                            |
| V-260532    | Medium   | Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.                                                 |
| V-260533    | Medium   | Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms.                                                                                                                                                                                                           |
| V-260540    | Medium   | Ubuntu 22.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.                                                                                                                                                                                                          |
| V-260542    | Medium   | Ubuntu 22.04 LTS must prevent direct login into the root account.                                                                                                                                                                                                                                            |
| V-260547    | Medium   | Ubuntu 22.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.                                                                                                                                                                                     |
| V-260549    | Low      | Ubuntu 22.04 LTS must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.                                                                                                                                          |
| V-260552    | Low      | Ubuntu 22.04 LTS must limit the number of concurrent sessions to ten for all accounts and/or account types.                                                                                                                                                                                                  |
| V-260554    | Medium   | Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity.                                                                                                                                                                                             |
| V-260611    | Medium   | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the fdisk command.                                                                                                                                                                                                  |
| V-260636    | Medium   | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module system call.                                                                                                                                                                                              |
| V-260640    | Medium   | Ubuntu 22.04 LTS must generate audit records for all events that affect the systemd journal files.                                                                                                                                                                                                           |

### usage

- `bosh cr && bosh ur`
- Edit the release version in the [runtime-config-stig](runtime-config-stig.yml)
- `bosh urc --name stig-compliance runtime-config-stig.yml`
- `Apply Changes`

