# vmware-vcf-sddcmgr-4x-stig-baseline
VMware Cloud Foundation SDDC Manager 4.x STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 4 Date: 2 May 2023  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the VCF SDDC Manager 4.4+ STIG Readiness Guide.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target. Tested with version 5.17.4. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target via root or sudo
- Update the inputs in inputs file example as appropriate for your environment
- assumes profile is downloaded to C:\Inspec\Profiles\vmware-vcf-sddcmgr-4x-stig-baseline**  
- assumes photon profile is downloaded to C:\Inspec\Profiles\vmware-photon-3.0-stig-inspec-baseline**  
- you may need to allow root ssh in order to run the profile since the vcf user cannot sudo. Remember to turn it back off afterwards.**
- an API bearer token is needed for the SDDC Manager Application controls to make API calls. Specify it on the command line or in the inputs file.**  

## Running the profile

#### Run all controls against a target appliance with example inputs and output results to CLI
```
inspec exec <Profile> -t ssh://root@IP or FQDN --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local
```

#### Run all controls in the profile against a target appliance and specify inputs with an inputs file
```
inspec exec <Profile> -t ssh://root@IPorFQDN -i <ssh key> --show-progress --input-file=inputs-vcf-sddc-mgr-4x.yml
```

#### Run all profiles against a target appliance with example inputs, show progress, and output results to CLI and JSON
```
inspec exec . -t ssh://root@IP or FQDN --password 'password' --input-file=inputs-vcf-sddc-mgr-4x.yml --show-progress --reporter=cli json:path\to\report\report.json
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
