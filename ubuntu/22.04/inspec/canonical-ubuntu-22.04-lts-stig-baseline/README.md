# canonical_ubuntu_22.04_lts_stig_baseline
Canonical Ubuntu 22.04 LTS STIG Chef InSpec Profile  
Version: Release 2 Version 4  
Date: 02 April 2025  
STIG Type: Official STIG  
Maintainers: Broadcom   


## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the Canonical Ubuntu 22.04 LTS STIG.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor (Recommended)](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target system or can be run against the local system. 
- Root or sudo access to the target system
- Update the inputs in inspec-example.yml or make a new copy and update as appropriate for your environment

## Inputs
Inputs are used to provide variable information that customize how the profile is ran against the target system. Below is a list of inputs available for this profile that can be provided.  

|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|temporary_accounts |[]                         |Temporary user account list.|Array|UBTU-22-411040|
|banner_text        |DOD Standard Banner        |Standard Mandatory DoD Notice and Consent Banner to display on login.|String|UBTU-22-255020,UBTU-22-271015|
|sudo_accounts      |[]                         |Array of users with authorized access to security functions that with sudo permissions.|Array|UBTU-22-432015|
|tmout              |900                        |Inactivity timeouts, in seconds, after which operating system automatically terminates a user session. >0 and <=900|Numeric|UBTU-22-412030|
|action_mail_acct   |root                       |Email to be notified when allocated audit record storage volume reaches capacity.|String|UBTU-22-653025,UBTU-22-653025|
|is_kdump_required  |false                      |Is kdump service required? (check with SA and documented with ISSO).|Boolean|UBTU-22-213015|
|audit_tools        |'/sbin/auditctl','/sbin/aureport','/sbin/ausearch','/sbin/autrace','/sbin/auditd','/sbin/augenrules'|Array of audit tools to check ownership and permissions.|Array|UBTU-22-232035,UBTU-22-232110|
|minimum_accepted_partition_size|8894028                |Set audit log size in bytes (default:1073741824 per control specification)|Numeric|UBTU-22-653035|
|aide_conf_path     |/etc/aide/aide.conf        |Path to aide.conf|String|UBTU-22-651030|
|maxlogins          |10                         |Maximum number of concurrent sessions in limits.conf|Numeric|UBTU-22-412020|
|is_system_networked|true                       |Set to true if the system is networked for NTP check|Boolean|UBTU-22-252010,UBTU-22-252015|
|sssd_conf_path     |/etc/sssd/sssd.conf        |Path to sssd.conf|String|UBTU-22-631015|
|approved_wireless_network_interfaces|[]                  |Array of approved wireless network interfaces|Array|UBTU-22-291015|
|chrony_conf_file_path|/etc/chrony/chrony.conf  |Path to chrony.conf|String|UBTU-22-252010,UBTU-22-252015|
|audit_sp_remote_server|Empty                   |Address of the remote syslog server to receive audit logs.|String|UBTU-22-653020|
|audit_offload_script_name|Empty                |Script file name for audit offload in cron.weekly|String|UBTU-22-651035|
|sshdcommand        |`sshd -T`                  |If a different sshd command is needed then supply a different input value such as if there are user matching rules.|String|All SSHD Rules|
|ao_approved_certificates |[]                   |Array list of root certificates present on the system and have been approved by the AO|Array|UBTU-22-631010|
|smartcards_used    |false                      |If smartcards are used for local logins set to true.|Boolean|UBTU-22-631015|

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
