# vmware-aria-operations-8.x-stig-baseline
VMware Aria Operations 8.x STIG Readiness Guide Chef InSpec Profile  
Version: Version 1 Release 2 Date: 19 July 2023  
STIG Type: STIG Readiness Guide
Maintainers: VMware  

## InSpec Profiles

InSpec profiles for VMware Aria Operations are available for each component or can be run all or some from the wrapper/overlay profile. Note the wrapper profile is setup to reference the other profiles from the same relative folder structure as seen here.    

Repository paths:
* [Photon](https://github.com/vmware/dod-compliance-and-automation/tree/master/photon/3.0/inspec/vmware-photon-3.0-stig-inspec-baseline)  

**Note - assumes all relevant profiles are downloaded to C:\Inspec\Profiles\vmware-stig-baseline**  
Example folder structure:  
```
\vmware-stig-baseline  
  \vmware-aria-operations-8.x-stig-baseline (this profile)   
  \vmware-photon-3.0-stig-inspec-baseline (overlay profile downloaded locally)  
```

[See the InSpec docs for more info on Profile dependencies and inheritence](https://www.inspec.io/docs/reference/profiles/)


## How to run InSpec locally from Powershell on Windows

**Note - assumes profiles are downloaded relative to C:\Inspec\Profiles\vmware-aria-operations-8.x-stig-inspec-baseline**  
**Note - update any needed inputs in each inspec.yaml or specify them at run time with the --inputs-file flag.**  

Run all profiles against a target appliance with needed inputs and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-aria-operations-8.x-stig-inspec-baseline -t ssh://root@IP or FQDN --password 'password'
```

Run all profiles in the current directory against a target appliance with needed inputs and output results to CLI
```
inspec exec . -t ssh://root@IP or FQDN --password 'password'
```

Run all profiles against a target appliance, specify a wrapper inputs file, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-aria-operations-8.x-stig-inspec-baseline -t ssh://root@IP or FQDN --password 'password' --input-file=inputs-example.yml --show-progress --reporter=cli json:C:\Inspec\Reports\report.json
```

Run a specific profile against a target appliance, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-aria-operations-8.x-stig-inspec-baseline\postgres -t ssh://root@IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\report.json
```

Run a specific profile against a target appliance, show progress, and output results to CLI and JSON using the wrapper profile
```
inspec exec C:\Inspec\Profiles\vmware-aria-operations-8.x-stig-inspec-baseline -t ssh://root@IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\report.json --controls=/VRPP/
```

Run a single STIG Control against a target appliance from a specific profile
```
inspec exec C:\Inspec\Profiles\vmware-aria-operations-8.x-stig-inspec-baseline\postgres -t ssh://root@IP or FQDN --password 'password' --controls=VRPP-8X-000001
```

Run all controls against a target appliance and specify a waiver file
```
inspec exec C:\Inspec\Profiles\vmware-aria-operations-8.x-stig-inspec-baseline\postgres -t ssh://root@IP or FQDN --password 'password' --waiver-file waiver-example.yml
```

## InSpec Vendoring

When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with 'inspec vendor --overwrite'
