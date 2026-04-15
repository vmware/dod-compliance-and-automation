# vmware-nsx-alb-stig-baseline
VMware NSX Advanced Load Balancer STIG Chef InSpec Profile  
Version: Release 1 Version 1 Date: 10th October 2023  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the NSX ALB STIG Readiness Guide.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target. Tested with version 5.22.4. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target
- Update the inputs in inputs file example as appropriate for your environment
- assumes profile is downloaded to C:\Inspec\Profiles\vmware-nsx-alb-stig-baseline**  
- an API token is needed for the tests to make API calls. Specify it on the command line or in the input file.See https://avinetworks.com/docs/latest/api-guide/ **

## Run the below command to generate the sessionid token
```
curl -d ‘{“username”:“admin”,“password”:“xxxxxx"}’ -H “Content-Type: application/json” -X POST https://<avicontroller IP or fqdn>/login -k -v
```
## Running the profile

#### Run all controls in the profile against a target deployment and specify inputs with an inputs file
```
inspec exec <Profile> --show-progress --input-file=inputs-nsx-alb-22.x.yml
```

#### Run all profiles against a target deployment with example inputs, show progress, and output results to CLI and JSON
```
inspec exec <Profile> --show-progress --input-file=inputs-nsx-alb-22.x.yml --reporter=cli json:path\to\report\report.json
```

#### Run a single STIG Control against a target deployment
```
inspec exec <Profile> --input-file=inputs-nsx-alb-22.x.yml --controls=NALB-SE-000077.rb
```

#### Run all controls in the profile against a target appliance and specify a waiver file 
```
inspec exec <Profile> --input-file=inputs-nsx-alb-22.x.yml --show-progress --waiver-file <waiverfile.yml>
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