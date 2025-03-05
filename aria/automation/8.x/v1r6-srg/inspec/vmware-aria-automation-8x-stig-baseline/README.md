# vmware-aria-automation-8x-stig-baseline
VMware Aria Automation 8.x STIG Readiness Guide Chef InSpec Profile  
Version: Version 1 Release 6 Date: 22 April 2024  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## InSpec Profiles
InSpec profiles for VMware Aria Operations are available for each component or can be run all or some from the wrapper/overlay profile. Note the wrapper profile is setup to reference the other profiles from the same relative folder structure as seen here.  

[See the InSpec docs for more info on Profile dependencies and inheritence](https://www.inspec.io/docs/reference/profiles/)

## Supported Versions
- 8.16.1-8.18

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target. Tested with cinc-auditor version 6.6.0. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target via root or sudo.
- Update the inputs in inputs file example (inspec.yml) as appropriate for your environment.
- Assumes profile is downloaded to C:\Inspec\Profiles\vmware-aria-automation-8x-stig-baseline  

## How to run InSpec locally from Powershell on Windows

Run all profiles against a target appliance and output results to CLI
```
cinc-auditor exec C:\Inspec\Profiles\vmware-aria-automation-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password'
```

Or if currently in the base directory ('vmware-aria-automation-8x-stig-baseline')
```
inspec exec . -t ssh://root@<IP or FQDN> --password 'password'
```

Run all profiles against a target appliance, specify a wrapper inputs file, show progress, and output results to CLI and JSON
```
cinc-auditor exec C:\Inspec\Profiles\vmware-aria-automation-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password' --input-file=inputs-example.yml --show-progress --reporter=cli json:C:\Inspec\Reports\report.json
```

Run a specific profile (Docker in this case, using a Regex) against a target appliance, show progress, and output results to CLI and JSON using the wrapper profile
```
cinc-auditor exec . -t ssh://root@<IP or FQDN> --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\aria-automation.json --controls=/DKER/
```

Run a single STIG Control against a target appliance from a specific profile
```
cinc-auditor exec . -t ssh://root@<IP or FQDN> --password 'password' --controls=VRAA-8X-000008
```

Run all controls against a target appliance and specify a waiver file
```
cinc-auditor exec . -t ssh://root@<IP or FQDN> --password 'password' --waiver-file waivers-aria-operations-8x-internal.yml
```

## InSpec Vendoring
When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with `inspec vendor --overwrite`

## Waivers
A set of example controls to 'skip' is provided for reference if controls should not be applied. (docker.rb, kubernetes.rb, photon.rb, and aria-automation.rb)
Other waiver options can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/), and an example waiver file is provided in the root of the repository.  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into a Mitre Heimdall server for a more polished visual result.
