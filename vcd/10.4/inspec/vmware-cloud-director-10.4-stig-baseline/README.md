# vmware-cloud-director-10.4-stig-baseline
VMware Cloud Director 10.4 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 1 Date: 14 July 2022  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the Cloud Director 10.4 STIG Readiness Guide.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target. Tested with version 4.41.20. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target via root or sudo
- Update the inputs in inputs file example as appropriate for your environment
- The root user cannot execute psql statements in the out of the box configuration and the postgres user does not have a password one will need to be set in order to audit psql through InSpec. # su - postgres $ /opt/vmware/vpostgres/10/bin/psql -c "alter user postgres with password 'your-password'"
- Two API bearer tokens are needed for the VCD Application controls to make API calls to both the VCD API and the Appliance API. Specify them on the command line or in the inputs file. See https://kb.vmware.com/s/article/56948 for generating a token for the application API
- The appliance API does not allow issued tokens to be used from different IPs it must be generated on the appliance you are running the profile against by running "curl -k -X POST -su root "https://<insert ip or name or localhost>:5480/api/1.0.0/sessions""

## Running the profile

#### Run all controls against a target appliance with example inputs and output results to CLI
```
inspec exec <Profile> -t ssh://root@IP or FQDN --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local
```

#### Run all controls in the profile against a target appliance and specify inputs with an inputs file
```
inspec exec <Profile> -t ssh://root@IPorFQDN -i <ssh key> --show-progress --input-file=inputs-vcd-10.4.yml
```

#### Run all profiles against a target appliance with example inputs, show progress, and output results to CLI and JSON
```
inspec exec . -t ssh://root@IP or FQDN --password 'password' --input-file=inputs-vcd-10.4.yml --show-progress --reporter=cli json:path\to\report\report.json
```

#### Run a single STIG Control against a target appliance
```
inspec exec <Profile> -t ssh://root@IP or FQDN --password 'password' --controls=PHTN-30-000001
```

#### Run all controls in the profile against a target appliance and specify a waiver file 
```
inspec exec <Profile> -t ssh://root@IPorFQDN -i <ssh key> --show-progress --waiver-file <waiverfile.yml>
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

## InSpec Vendoring

When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with "inspec vendor --overwrite"
