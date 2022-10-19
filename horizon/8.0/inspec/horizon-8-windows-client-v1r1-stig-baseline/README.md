# horizon-8-client-stig-baseline
Horizon 8 Client STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 1 Date: 10 Oct 2022  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the Horizon 8 Client STIG Readiness Guide.

It has been tested against versions 8.4 and 8.6 (2206). Note - Some content may be absent such as Vulnerability IDs for draft content and will be added once released by DISA. 

All technical NIST SP 800-53 requirements were considered while developing this content. SRG requirements that are applicable and configurable are included in this content while other controls that are "Not Applicable", "Inherently Met" or "Does Not Meet" are not included.

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed either on the machine to be tested, or on a machine that can create a winrm session the machine to be tested. Tested with InSpec version 5.10.5. Chef/CINC Workstation can also be installed and used.
- Administrative access to the machine to be tested.
- Update the inputs in the inspec.yml file as appropriate for the environment.
- InSpec installed on target machine if running tests locally, or winrm enabled on the target machine if running tests remotely.

## Running the profile specifying the transport at the command line

#### Run all controls in the profile against a target node using winrm
```
inspec exec <Profile> -t winrm://<ip address> --user <username> --password '<password>' --show-progress
```

#### Run all controls in the profile against a target node using winrm and output results to JSON
```
inspec exec <Profile> -t winrm://<ip address> --user <username> --password '<password>' --show-progress --reporter cli json:results.json
```

#### Run a subset or a single control in the profile against a target node using winrm
```
inspec exec <Profile> -t winrm://<ip address> --user <username> --password '<password>' --show-progress --controls=<control id>
```

#### Run all controls in the profile against a target node and specify a waiver file 
```
inspec exec <Profile> -t winrm://<ip address> --user <username> --password '<password>' --show-progress --waiver-file <waiverfile.yml>
```

## Running the profile and providing or prompting for inputs (user, password, fqdn)

#### Run all controls in the profile against a target node (creates a winrm connection) - no inputs
```
inspec exec <Profile> --show-progress
```

#### Run all controls in the profile against a target node (creates a winrm connection) - some inputs
```
inspec exec <Profile> --input user=<user>,fqdn=<fqdn> --show-progress
```

#### Run all controls in the profile against a target node (creates a winrm connection) - all inputs
```
inspec exec <Profile> --input user=<user>,fqdn=<fqdn>,password=<password> --show-progress
```

## Running the profile locally

#### Run all controls in the profile on the target machine (requires inspec installed on target machine)
```
inspec exec <Profile> --input runlocal=true --show-progress
```

**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.  

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's inspec_tools](https://github.com/mitre/inspec_tools) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into Heimdall server for a more polished visual report.  

## Disclaimer

VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA imply no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architecture level. Some of the controls may not be configurable or applicable in certain environments.

## License

The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](./LICENSE).
