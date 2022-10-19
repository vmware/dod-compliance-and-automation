# uag-photon-3.0-stig-inspec-baseline
Unified Access Gateway Photon 3.0 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 1 Date: 10 Oct 2022  
STIG Type: STIG Readiness Guide  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the Unified Access Gateway Photon 3.0 STIG Readiness Guide. 

It has been tested against UAG versions 2203, 2207, and 2209. Note - Some content may be absent such as Vulnerability IDs for draft content and will be added once released by DISA. 

All technical NIST SP 800-53 requirements were considered while developing this content. SRG requirements that are applicable and configurable are included in this content while other controls that are "Not Applicable", "Inherently Met" or "Does Not Meet" are not included.

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed either on the machine to be tested, or on a machine that can create a winrm session the machine to be tested. Tested with InSpec version 5.10.5. Chef/CINC Workstation can also be installed and used.
- Update the inputs in the inspec.yml file as appropriate for the environment.

## Running Inspec

**Note - commands assume you have downloaded the profile and the current directory is the profile folder**  

Run all controls against a target Photon OS server using inputs as provided in the inspec.yml file
```
inspec exec <Profile> -t ssh://root@[photon IP or FQDN] --password 'password'
```

Run all controls against a target Photon OS server with example inputs and output results to CLI
```
inspec exec <Profile> -t ssh://root@[photon IP or FQDN] --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local
```

Run all profiles against a target Photon OS server with example inputs, show progress, and output results to CLI and JSON
```
inspec exec <Profile> -t ssh://root@[photon IP or FQDN] --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local --show-progress --reporter=cli json:path\to\report\photon.json
```

Run a single STIG Control against a target Photon OS server
```
inspec exec <Profile> -t ssh://root@[photon IP or FQDN] --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local --controls=PHTN-30-000001
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
