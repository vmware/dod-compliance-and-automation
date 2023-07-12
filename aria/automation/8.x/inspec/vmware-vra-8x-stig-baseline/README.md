# vmware-vra-8x-stig-baseline
VMware vRealize Automation 8.x STIG Readiness Guide Chef InSpec Profile  
Version: Version 1 Release 3 Date: 6 April 2023  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the VMware vRealize Automation 8.x STIG Readiness Guide.

It has been tested against versions 8.6 through 8.11.1. 

All technical NIST SP 800-53 requirements were considered while developing this content. SRG requirements that are applicable and configurable are included in this content while other controls that are "Not Applicable", "Inherently Met" or "Does Not Meet" are not included.

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed either on the machine to be tested, or on a machine that can create a winrm session the machine to be tested. Tested with InSpec version 5.21.29. Chef/CINC Workstation can also be installed and used.
- Administrative access to the machine to be tested.
- Update the inputs in the inspec.yml file as appropriate for the environment.
- InSpec installed on target machine if running tests locally, or ssh enabled on the target machine if running tests remotely.

## vRA InSpec Profiles

InSpec profiles for vRA are available for each component or can be run all or some from the wrapper/overlay profile. Note the wrapper profile is setup to reference the other profiles from the same relative folder structure as seen below.  

Repository paths:
* [Photon](https://github.com/vmware/dod-compliance-and-automation/tree/master/photon/3.0/inspec/vmware-photon-3.0-stig-inspec-baseline)

See the [InSpec docs](https://www.inspec.io/docs/reference/profiles/) for more info on profile dependencies and inheritance  

## How to run InSpec locally from Powershell on Windows

**Note - assumes all relevant profiles are downloaded to C:\Inspec\Profiles\vmware-vra-8x-stig-baseline**  
Example folder structure:  
```
\vmware-vra-8x-stig-baseline  
  \docker  
  \kubernetes  
  \photon  
  \vra  
```
**Note - update any needed inputs in each inspec.yaml or specify them at run time.**  

It is recommended to utilize an inputs file for specifying environment specific variables such as NTP, Syslog, etc. An example is provided for you to begin with.  

### Run all profiles against a target vRA appliance and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-vra-8x-stig-baseline -t ssh://root@vra IP or FQDN --password 'password'
```

### Or if currently in the base directory ('vmware-vra-8x-stig-baseline')
```
inspec exec . -t ssh://root@vra IP or FQDN --password 'password'
```
### Run all profiles against a target vRA appliance with needed inputs and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-vra-8x-stig-baseline -t ssh://root@vra IP or FQDN --password 'password' --input [nputname]=[inputvalue] [inputname]=[inputvalue]
```
### Run all profiles against a target appliance with example inputs, show progress, and output results to CLI and JSON
```
inspec exec . -t ssh://root@IP or FQDN --password 'password' --input-file=inputs-example.yml --show-progress --reporter=cli json:path\to\report\report.json
```
### Run all profiles against a target vRA, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-vra-8x-stig-baseline -t ssh://root@vra IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vra.json
```
### Run a specific profile (Docker in this case, using a Regex) against a target vRA appliance, show progress, and output results to CLI and JSON using the wrapper profile
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-vra-8x-stig-baseline -t ssh://root@vra IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vra.json --controls=/DKER/
```
### Run a single STIG Control against a target vRA appliance from a specific profile
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-vra-8x-stig-baseline -t ssh://root@vra IP or FQDN --password 'password' --controls=VRAA-8X-000008
```

## Waivers
A set of example controls to 'skip' is provided for reference if controls should not be applied. (docker.rb, kubernetes.rb, photon.rb, and vra.rb)
Other waiver options can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into Heimdall server for a more polished visual result.  

## InSpec Vendoring

**Note - When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.**  
**This lockfile creation can be prevented by adding the '--no-create-lockfile' parameter to any of the above InSpec commands.**

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with 'inspec vendor --overwrite'