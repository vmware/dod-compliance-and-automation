# vmware-aria-operations-for-logs-8.x-stig-baseline
VMware Aria Operations for Logs 8.14 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 3 Date: 22 December 2023  
STIG Type: STIG Readiness Guide
Maintainers: SCOPE/VMTA  

## Targets
This version of the content is currently applicable for VMware Aria Operations for Logs versions 8.14, and will be updated as necessary for later releases.

## VMware Aria Operations for Logs InSpec Profiles

InSpec profiles for VMware Aria Operations for Logs are available for each component or can be run all or some from the wrapper/overlay profile. Note the wrapper profile is setup to reference the other profiles from the same relative folder structure as seen below.  

Repository paths:
* [Photon 4.0](https://github.com/vmware/dod-compliance-and-automation/tree/master/photon/4.0/inspec/vmware-photon-4.0-stig-baseline)

[See the InSpec docs for more info on Profile dependencies and inheritence](https://www.inspec.io/docs/reference/profiles/)


## How to run InSpec locally from Powershell on Windows

**Note - assumes profiles are downloaded to C:\Inspec\Profiles\vmware-stig-baseline.  Photon profile must be downloaded and staged appropriately.**  
Example folder structure:  
```
\vmware-stig-baseline  
  \vmware-aria-operations-for-logs-8x-stig-baseline  
    \ariaoplogs
    \cassandra
    \controls
    \tcserver
  \vmware-photon-4.0-stig-baseline  
```

**Note - update any needed inputs in each inspec.yaml or specify them at run time.**  

It is recommended to utilize an inputs file for specifying environment specific variables such as NTP, Syslog, etc. An example (inputs-example.yml) is provided in the root directory for you to begin with.  See the command line examples below for usage examples.  


Run all profiles against a target appliance and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-stig-baseline\vmware-aria-operations-for-logs-8x-stig-baseline -t ssh://root@<IP or FQDN> --password 'password'
```

Or if currently in the base directory ('vmware-aria-operations-for-logs-8x-stig-baseline')
```
inspec exec . -t ssh://root@<IP or FQDN> --password 'password'
```

Run all profiles against a target appliance with needed inputs, show progress, and output results to CLI and JSON
```
inspec exec . -t ssh://root@<IP or FQDN> --password 'password' --show-progress --input [nputname]=[inputvalue] [inputname]=[inputvalue] --reporter=cli json:C:\Inspec\Reports\report.json
```

Run a specific profile against a target appliance with input file and output results to CLI and JSON
```
inspec exec .\tcserver -t ssh://root@<IP or FQDN> --password 'password' --input-file .\inputs-example.yml --reporter=cli json:C:\Inspec\Reports\report.json
```

Run a single control against a target appliance with input file and output results to CLI
```
inspec exec . -t ssh://root@<IP or FQDN> --password 'password' --input-file .\inputs-example.yml --controls=VLIA-8X-000001
```

Run a specific set of controls from a specific profile using regex against a target appliance
```
inspec exec .\cassandra -t ssh://root@<IP or FQDN> --password 'password' --controls=/VLIC-8X-00001/
(or /VLIC/, etc)
```

## Waivers
A set of controls to 'skip' can be utilized if controls should not be applied.
See examples and other waiver options in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/).  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  


## InSpec Vendoring

**Note - When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.**  
**This lockfile creation can be prevented by adding the '--no-create-lockfile' parameter to any of the above InSpec commands.**

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated by running the "inspec vendor --overwrite" command.
