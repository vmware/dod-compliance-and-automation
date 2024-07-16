# vmware-vcsa-8.0-stig-baseline
VMware vSphere vCenter Appliance 8.0 STIG Chef InSpec Profile  
Version: Release 2 Version 1 Date: 01 August 2024  
STIG Type: Official STIG

## VCSA InSpec Profiles
InSpec profiles for the VCSA are available for each component or can be run all or some from the wrapper/overlay profile. Note the wrapper profile is setup to reference the other profiles from the same relative folder structure as seen here.  
[See the InSpec docs for more info on Profile dependencies and inheritance](https://www.inspec.io/docs/reference/profiles/)

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that has PowerCLI 13+ installed. Tested with version 6.6.0. Chef/CINC Workstation can also be installed and used.  
- SSH enabled on the vCenter appliance and the bash shell set to the default for the root account. This should be reverted once scanning is complete.

## How to run InSpec locally from Powershell on Windows

**Note - assumes vcsa profiles are downloaded to C:\Inspec\Profiles\vmware-vcsa-8.0-stig-baseline**  

Run all profiles against a target vCenter appliance and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-8.0-stig-baseline -t ssh://root@vcsa IP or FQDN --password 'password'
```

Run all profiles against a target vCenter appliance, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-8.0-stig-baseline -t ssh://root@vcsa IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json
```

Run a specific profile against a target vCenter appliance show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-8.0-stig-baseline\eam -t ssh://root@vcsa IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json
```

Run a specific profile (EAM in this case) against a target vCenter appliance show progress, and output results to CLI and JSON using the wrapper profile
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-8.0-stig-baseline -t ssh://root@vcsa IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json --controls=/VCEM/
```

Run a single STIG Control against a target vCenter appliance from a specific profile
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-8.0-stig-baseline\eam -t ssh://root@vcsa IP or FQDN --password 'password' --controls=VCEM-70-000001
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
