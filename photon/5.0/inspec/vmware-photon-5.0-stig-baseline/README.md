# vmware-photon-5.0-stig-baseline
Photon OS 5.0 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 2 Date: 12 September 2023  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the Photon OS 5.0 STIG Readiness Guide.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH target node. Tested with version 5.22.3. Chef/CINC Workstation can also be installed and used.
- SSH access to Photon instance
- Update the inputs in inspec-example.yml or make a new copy and update as appropriate for your environment

## Running the profile

#### Run all controls in the profile against a target server with an SSH Key
```
inspec exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --show-progress --input-file inputs-example.yml
```

#### Run all controls in the profile against a target server with a password
```
inspec exec <Profile> -t ssh://USER@IPorFQDN --password '<password>' --show-progress --input-file inputs-example.yml
```

#### Run all controls in the profile against a target server and output results to JSON
```
inspec exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --show-progress --input-file inputs-example.yml --reporter cli json:/tmp/results.json
```

#### Run all controls in the profile against a target server and specify inputs on the command line
```
inspec exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --show-progress --input inputname1=somevalue1 inputname2=somevalue2
```

#### Run a subset or a single control in the profile against a target server 
```
inspec exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --show-progress --controls=<control id> --input-file inputs-example.yml
```

#### Run all controls in the profile against a target server and specify a waiver file 
```
inspec exec <Profile> -t ssh://USER@IPorFQDN -i <ssh key> --show-progress --waiver-file <waiverfile.yml> --input-file inputs-example.yml
```

**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.  

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into [MITRE's Heimdall](https://github.com/mitre/heimdall2) server for a more polished visual result.  
