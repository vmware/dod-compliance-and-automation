# xenial-stig-compliance-release

 <a name="warning">:warning:  The `jammy-compliance-release` is not compatible with `auditd` job in [os-conf-release](https://github.com/cloudfoundry/os-conf-release)</a>

### fixes

| VID | Title|
|---|---|
| V-90123  | The Ubuntu operating system must limit the number of concurrent sessions to ten for all accounts and/or account types. |
| V-90153  | Passwords for new users must have a 60-day maximum password lifetime restriction. |
| V-90157  | Passwords must have a minimum of 15-characters. |
| V-90165  | Account identifiers (individuals, groups, roles, and devices) must disabled after 35 days of inactivity. |
| V-90167  | The Ubuntu operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts. |
| V-90225  | The Ubuntu operating system must not have unnecessary accounts. |
| V-90241  | All local interactive user accounts, upon creation, must be assigned a home directory. |
| V-90249  | All local initialization files must have mode 0740 or less permissive. |
| V-90371  | Successful/unsuccessful uses of the su command must generate an audit record. |
| V-90373  | Successful/unsuccessful uses of the chfn command must generate an audit record. |
| V-90375  | Successful/unsuccessful uses of the mount command must generate an audit record. |
| V-90377  | Successful/unsuccessful uses of the umount command must generate an audit record. |
| V-90379  | Successful/unsuccessful uses of the ssh-agent command must generate an audit record. |
| V-90387  | Successful/unsuccessful uses of the ssh-keysign command must generate an audit record. |
| V-90397  | The audit system must be configured to audit any usage of the setxattr system call. |
| V-90399  | The audit system must be configured to audit any usage of the lsetxattr system call. |
| V-90401  | The audit system must be configured to audit any usage of the fsetxattr system call. |
| V-90403  | The audit system must be configured to audit any usage of the removexattr system call. |
| V-90405  | The audit system must be configured to audit any usage of the lremovexattr system call. |
| V-90407  | The audit system must be configured to audit any usage of the fremovexattr system call. |
| V-90409  | Successful/unsuccessful uses of the chown command must generate an audit record. |
| V-90411  | Successful/unsuccessful uses of the fchown command must generate an audit record. |
| V-90413  | Successful/unsuccessful uses of the fchownat command must generate an audit record. |
| V-90415  | Successful/unsuccessful uses of the lchown command must generate an audit record. |
| V-90423  | Successful/unsuccessful uses of the open command must generate an audit record. |
| V-90425  | Successful/unsuccessful uses of the truncate command must generate an audit record. |
| V-90427  | Successful/unsuccessful uses of the ftruncate command must generate an audit record. |
| V-90429  | Successful/unsuccessful uses of the creat command must generate an audit record. |
| V-90431  | Successful/unsuccessful uses of the openat command must generate an audit record. |
| V-90433  | Successful/unsuccessful uses of the open_by_handle_at command must generate an audit record. |
| V-90435  | Successful/unsuccessful uses of the sudo command must generate an audit record. |
| V-90439  | Successful/unsuccessful uses of the chsh command must generate an audit record. |
| V-90441  | Successful/unsuccessful uses of the newgrp command must generate an audit record. |
| V-90445  | Successful/unsuccessful uses of the apparmor_parser command must generate an audit record. |
| V-90447  | Successful/unsuccessful uses of the setfacl command must generate an audit record. |
| V-90449  | Successful/unsuccessful uses of the chacl command must generate an audit record. |
| V-90457  | Successful/unsuccessful uses of the passwd command must generate an audit record. |
| V-90461  | Successful/unsuccessful uses of the gpasswd command must generate an audit record. |
| V-90463  | Successful/unsuccessful uses of the chage command must generate an audit record. |
| V-90465  | Successful/unsuccessful uses of the usermod command must generate an audit record. |
| V-90467  | Successful/unsuccessful uses of the crontab command must generate an audit record. |
| V-90469  | Successful/unsuccessful uses of the pam_timestamp_check command must generate an audit record. |
| V-90471  | Successful/unsuccessful uses of the init_module command must generate an audit record. |
| V-90473  | Successful/unsuccessful uses of the finit_module command must generate an audit record. |
| V-90475  | Successful/unsuccessful uses of the delete_module command must generate an audit record. |
| V-90509  | The Ubuntu operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections. |
| V-90511  | The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms. |
| V-90517  | The Ubuntu operating system must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements. |
| V-90521  | The SSH daemon must not allow authentication using known hosts authentication. |
| V-90531  | The SSH daemon must not allow compression or must only allow compression after successful authentication. |
| V-90533  | The Ubuntu operating system must be configured so that remote X connections are disabled unless to fulfill documented and validated mission requirements. |
| V-95681  | Successful/unsuccessful uses of the chcon command must generate an audit record. |

### usage
- `bosh cr && bosh ur`
- Edit the release versionin the [runtime-config-stig](runtime-config-stig.yml)
- `bosh urc --name stig-compliance runtime-config-stig.yml`
- `Apply Changes`