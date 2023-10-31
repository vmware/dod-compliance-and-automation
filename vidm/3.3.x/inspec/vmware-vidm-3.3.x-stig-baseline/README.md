# vmware-vidm-3.3.x-stig-baseline
VMware Identity Manager 3.3.x STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 2 Date: 29 August 2023  
STIG Type: STIG Readiness Guide

## InSpec Profiles

InSpec profiles for vIDM are available for each component or can be run all or some from the wrapper/overlay profile. Note the wrapper profile is setup to reference the other profiles from the same relative folder structure as seen here.  

[See the InSpec docs for more info on Profile dependencies and inheritance](https://www.inspec.io/docs/reference/profiles/)

## How to run InSpec locally from Powershell on Windows

**Note - assumes vIDM profile is downloaded to C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline**  
**Note - assumes photon profile is downloaded to C:\Inspec\Profiles\vmware-photon-3.0-stig-inspec-baseline**  
**Note: Root SSH is disabled by default on the vIDM appliances and the sshuser account can be used instead with the sudo options shown in the example commands.**  

It is recommended to utilize an inputs files for specifying vIDM and environment specific variables. An example is provided for you to begin with.  

Run all profiles against a target appliance and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password'
```

Run all profiles against a target appliance, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vidm.json
```

Run a specific profile against a target appliance show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vidm.json
```

Run a specific profile (EAM in this case) against a target appliance show progress, and output results to CLI and JSON using the wrapper profile
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vidm.json --controls=/WOAD/
```

Run a single STIG Control against a target appliance from a specific profile
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --controls=WOAD-3X-000001
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
