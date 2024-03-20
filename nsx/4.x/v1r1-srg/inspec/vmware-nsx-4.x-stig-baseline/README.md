# vmware-nsx-4.x-stig-baseline
VMware NSX 4.x STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 1 Date: 07 March 2023  
STIG Type: STIG Readiness Guide  
Maintainers: VMware       

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the NSX 4.x STIG.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target. Tested with version 5.18.14. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target
- Create an inputs file for your environment. See the inputs-example.yml file. 
- An API token is needed for the tests to make API calls. Specify it on the command line or in the inputs file.  See https://developer.vmware.com/apis/1248/nsx-t **  
- This profile uses the local transport to run API calls against an NSX Manager deployment.

## Running the profile

#### Run all controls in the profile against a target deployment and specify inputs with an inputs file
```
inspec exec <Profile> --show-progress --input-file=inputs-nsx-4.x-example.yml
```

#### Run all profiles against a target deployment with example inputs, show progress, and output results to CLI and JSON
```
inspec exec <Profile> --show-progress --input-file=inputs-nsx-4.x-example.yml --reporter=cli json:path\to\report\report.json
```

#### Run a single STIG Control against a target deployment
```
inspec exec <Profile> --input-file=inputs-nsx-4.x-example.yml --controls=T0FW-4X-000002
```

#### Run all controls in the profile against a target appliance and specify a waiver file 
```
inspec exec <Profile> --input-file=inputs-nsx-4.x-example.yml --show-progress --waiver-file <waiverfile.yml>
```

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into [MITRE's Heimdall](https://github.com/mitre/heimdall2) server for a more polished visual result.

## InSpec Vendoring

When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with inspec vendor --overwrite
