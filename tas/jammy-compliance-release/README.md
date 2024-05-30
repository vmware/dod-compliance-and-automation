# jammy-compliance-release
 <a name="warning">:warning:  The `jammy-compliance-release` is not compatible with `auditd` job in [os-conf-release](https://github.com/cloudfoundry/os-conf-release)</a>

## CIS
The `cis` job is intended to be used to change stemcell configutation to pass the Jammy CIS rules. Below is a list of variables that can be set in the [runtime-config](./runtime-config-cis.yml) for configurations based on your deployment compliance requirements.
|variable| description|default|
|--|---|--|
|`set_password_max_days`| set `PASS_MAX_DAYS` in `/etc/login.defs`| `false`|
|`password_max_days`|Applicable if `set_password_max_days` is set to `true`. If set, passwords will expire once they reach max days.| `30`|
|`set_useradd_inactive`| set `INACTIVE` value for `useradd`|`false`|
|`useradd_inactive`| Applicable if `set_useradd_inactive` is set to `true`. If set, user accounts that have been inactive for over a given period of time can be automatically disabled.| `30` |
|`set_user_shell_timeout`| set default user shell timeout| `false`|
|`user_shell_timeout`| Applicable if `set_useradd_inactive` is set to `true`. User shell timeout in seconds| `900`|
|`restirct_su`| If set to `true`,  `group` key for `pam_wheel.so` statement in `/etc/pam.d/su` will be set to a group with no users. This group is intentionally empty to reinforce the use of `sudo` instead of `su` for privileged access.| `false`|
|`make_audit_rules_immutable`| If set to `true`, this job will make audit rules immutable. Any change to auditd rules will require a reboot. Also see :warning: [warning](#warning) above. `auditd` job in `os-conf-release` also sets audit rules to be immutable. | `false`|

### usage
- `bosh cr && bosh ur`
- Edit the release version and variables in the [runtime-config-cis](runtime-config-cis.yml)
- `bosh urc --name cis-compliance runtime-config-cis.yml`
- `Apply Changes`

## STIG
The `stig` is intended to be used to change the stemcell configurations to pass Bionic STIG rules, since a Jammy STIG has not been published yet

### usage
- `bosh cr && bosh ur`
- Edit the release versionin the [runtime-config-stig](runtime-config-stig.yml)
- `bosh urc --name stig-compliance runtime-config-stig.yml`
- `Apply Changes`

