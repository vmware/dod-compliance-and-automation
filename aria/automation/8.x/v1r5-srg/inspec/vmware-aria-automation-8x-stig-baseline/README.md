# vmware-aria-automation-8x-stig-baseline
VMware Aria Automation 8.x STIG Readiness Guide Chef InSpec Profile  
Version: Version 1 Release 5 Date: 03 January 2024  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the VMware Aria Automation 8.x STIG Readiness Guide.

It has been tested against version 8.13.1. 

All technical NIST SP 800-53 requirements were considered while developing this content. SRG requirements that are applicable and configurable are included in this content while other controls that are "Not Applicable", "Inherently Met" or "Does Not Meet" are not included.

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed either on the machine to be tested, or on a machine that can create a winrm session the machine to be tested. Tested with InSpec version 5.21.29. Chef/CINC Workstation can also be installed and used.
- Administrative access to the machine to be tested.
- Update the inputs in the inspec.yml file as appropriate for the environment.
- InSpec installed on target machine if running tests locally, or ssh enabled on the target machine if running tests remotely.

## How to run InSpec locally from Powershell on Windows

**Note - assumes all relevant profiles are downloaded to C:\Inspec\Profiles\vmware-aria-automation-8x-stig-baseline**  
Example folder structure:  
```
\vmware-aria-automation-8x-stig-baseline  
  \docker  
  \kubernetes  
  \photon  
  \vra  
```
**Note - update any needed inputs in each inspec.yaml or specify them at run time.**  

**NOTE: The Official DISA Kubernetes STIG guidance must be modified if running manual checks. Please see the Overview file in the documentation located [here](https://github.com/vmware/dod-compliance-and-automation/blob/master/aria/automation/8.x/docs/VMware_Aria_Automation_8.x_V1R5_STIG_Readiness_Guide_xccdf.zip)**

It is recommended to utilize an inputs file for specifying environment specific variables such as NTP, Syslog, etc. An example is provided for you to begin with.  

### Run all profiles against a target appliance and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-aria-automation-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password'
```

### Or if currently in the base directory ('vmware-aria-automation-8x-stig-baseline')
```
inspec exec . -t ssh://root@<IP or FQDN> --password 'password'
```

### Run all profiles against a target appliance with needed inputs and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-aria-automation-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password' --input [nputname]=[inputvalue] [inputname]=[inputvalue]
```

### Run all profiles against a target appliance with example inputs, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-aria-automation-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password' --input-file=inputs-example.yml --show-progress --reporter=cli json:path\to\report\report.json
```

### Run all profiles against a target appliance, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-aria-automation-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\aria-automation.json
```

### Run a specific profile (Docker in this case, using a Regex) against a target appliance, show progress, and output results to CLI and JSON using the wrapper profile
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-aria-automation-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\aria-automation.json --controls=/DKER/
```

### Run a single STIG Control against a target appliance from a specific profile
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-aria-automation-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password' --controls=VRAA-8X-000008
```

## Waivers
A set of example controls to 'skip' is provided for reference if controls should not be applied. (docker.rb, kubernetes.rb, photon.rb, and aria-automation.rb)
Other waiver options can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/), and an example waiver file is provided in the root of the repository.  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into a Heimdall server for a more polished visual result.

## InSpec Vendoring

**Note - When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.**  
**This lockfile creation can be prevented by adding the '--no-create-lockfile' parameter to any of the above InSpec commands.**

If you add or update dependencies in inspec.yml, dependencies can be re-vendored and the lockfile updated by running the "inspec vendor --overwrite" command.
