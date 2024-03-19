[![pipeline status](https://gitlab.eng.vmware.com/compliance-automation/stig/nsx-t/vmware-nsxt-3.x-stig-baseline/badges/master/pipeline.svg)](https://gitlab.eng.vmware.com/compliance-automation/stig/nsx-t/vmware-nsxt-3.x-stig-baseline/-/commits/master)
# vmware-nsxt-3.x-stig-baseline
VMware NSX-T 3.x STIG Chef InSpec Profile  
Version: Release 1 Version 3 Date: 26 July 2023 
STIG Type: [Official STIG](https://confluence.eng.vmware.com/pages/viewpage.action?pageId=1231779155)  
Maintainers: SCOPE/VMTA  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the NSX-T 3.x STIG.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target. Tested with version 5.18.14. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target
- Update the inputs in inputs file example as appropriate for your environment
- assumes profile is downloaded to C:\Inspec\Profiles\vmware-nsxt-3.x-stig-baseline**  
- an API token is needed for the tests to make API calls. Specify it on the command line or in the inputs file.  See https://developer.vmware.com/apis/1248/nsx-t **  

## Running the profile

#### Run all controls in the profile against a target deployment and specify inputs with an inputs file
```
inspec exec <Profile> --show-progress --input-file=inputs-nsxt-3.x.yml
```

#### Run all profiles against a target deployment with example inputs, show progress, and output results to CLI and JSON
```
inspec exec <Profile> --show-progress --input-file=inputs-nsxt-3.x.yml --reporter=cli json:path\to\report\report.json
```

#### Run a single STIG Control against a target deployment
```
inspec exec <Profile> --input-file=inputs-nsxt-3.x.yml --controls=T0FW-3X-000002
```

#### Run all controls in the profile against a target appliance and specify a waiver file 
```
inspec exec <Profile> --input-file=inputs-nsxt-3.x.yml --show-progress --waiver-file <waiverfile.yml>
```

## Misc

Please review the inspec.yml for input variables and specify at runtime or via an inputs.yml file

## InSpec Profile Overlays

If changes are needed to skip controls or update checks it is recommended to create an overlay profile that has a dependency on this profile with the needed changes so they can be easily tracked 

[See the InSpec docs for more info on Profile dependencies and inheritance](https://www.inspec.io/docs/reference/profiles/)

**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into Heimdall server for a more polished visual result.

A VMTA hosted Heimdall server is available at [VMTA Heimdall](https://heimdall.eng.vmware.com)

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into Heimdall server for a more polished visual result.

A VMTA hosted Heimdall server is available at [VMTA Heimdall](https://heimdall.eng.vmware.com)

## InSpec Vendoring

When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with "inspec vendor --overwrite"
