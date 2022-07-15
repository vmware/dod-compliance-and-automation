# vmware-photon-3.0-stig-baseline
VMware Photon OS 3.0 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 5 Date: 27 June 2022  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the Photon OS 3.0 STIG Readiness Guide.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target. Tested with version 4.41.20. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target via root or sudo
- Update the inputs in inspec.yml as appropriate for your environment

## Running the profile

#### Run all controls against a target Photon OS server with example inputs and output results to CLI
```
inspec exec <Profile> -t ssh://root@photon IP or FQDN --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local
```

#### Run all controls in the profile against a target server and specify inputs with an inputs file
```
inspec exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --show-progress --input-file=inputs-vcenter-7.0.yml
```

#### Run all profiles against a target Photon OS server with example inputs, show progress, and output results to CLI and JSON
```
inspec exec . -t ssh://root@photon IP or FQDN --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local --show-progress --reporter=cli json:path\to\report\photon.json
```

#### Run a single STIG Control against a target Photon OS server
```
inspec exec <Profile> -t ssh://root@photon IP or FQDN --password 'password' --controls=PHTN-30-000001
```

#### Run all controls in the profile against a target server and specify a waiver file 
```
inspec exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --show-progress --waiver-file <waiverfile.yml>
```

## Misc

Please review the inspec.yml for input variables and specify at runtime or via an inputs.yml file

## InSpec Profile Overlays

If changes are needed to skip controls or update checks it is recommended to create an overlay profile that has a dependency on this profile with the needed changes so they can be easily tracked 

[See the InSpec docs for more info on Profile dependencies and inheritence](https://www.inspec.io/docs/reference/profiles/)

**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.  

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into [MITRE's Heimdall](https://github.com/mitre/heimdall2) server for a more polished visual result.

## Control Coverage
The following tables details the controls that must be manually checked and are not covered by this profile.

| STIG ID | Title |
|---------|-------|
