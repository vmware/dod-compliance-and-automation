# jammy-stig-compliance-release
 <a name="warning">:warning:  The `jammy-compliance-release` is not compatible with `auditd` job in [os-conf-release](https://github.com/cloudfoundry/os-conf-release)</a>

## STIG
The `stig` is intended to be used to change the stemcell configurations to pass Bionic STIG rules, since a Jammy STIG has not been published yet

### fixes
Following controls are fixed by this release
- V-238309: The Ubuntu operating system must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access.
- V-238216: The Ubuntu operating system must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
- V-238217: The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
- V-255912: The Ubuntu operating system SSH server must be configured to use only FIPS-validated key exchange algorithms.

### false positives
- V-238258
  The audit rules exits. To verify run:
  1. `# grep setxattr /etc/audit/audit.rules | grep fsetxattr | grep lsetxattr | grep removexattr | grep fremovexattr | grep lremovexattr`
    
      and verify the output contains
      
      ```
      -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
      -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
      ``` 
  2. `# auditctl -l  | grep setxattr | grep fsetxattr |grep lsetxattr | grep removexattr | grep fremovexattr | grep lremovexattr`

      and verify the output contains

      ```
      -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
      -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
      ``` 
### usage
- `bosh cr && bosh ur`
- Edit the release versionin the [runtime-config-stig](runtime-config-stig.yml)
- `bosh urc --name stig-compliance runtime-config-stig.yml`
- `Apply Changes`

