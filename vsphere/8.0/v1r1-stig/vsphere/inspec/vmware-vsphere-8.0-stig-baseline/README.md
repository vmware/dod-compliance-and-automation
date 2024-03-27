# vmware-vsphere-8.0-stig-baseline
VMware vSphere vCenter Appliance 8.0 STIG Chef InSpec Profile  
InSpec profile for vSphere 8.0 vCenter, ESXi, and VM controls. Does not include appliance level controls  
Version: Release 1 Version 1 Date: 03 November 2023  
STIG Type: Official STIG  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the vSphere 8.0 vCenter, ESXi, and VM STIG controls. Does not include appliance level controls.  

## Requirements

- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that has PowerCLI 13+ installed. Tested with version 5.18.14. Chef/CINC Workstation can also be installed and used.  
- If ran on a system with Powershell Core installed that is Version 7.2.1 or greater then run the following command first "$env:NO_COLOR=$true" . Newer versions of Powershell Core show ANSI escape characters differently and that causes issues with how the VMware train parses output.  
- Create an inputs file for your environment. See the inputs-example.yml file.  
- For ESXi you can run it against a single host, all hosts in a cluster, or all hosts in a vCenter based on the inputs you provide.  
- For VMs you can run against a single VM or all VMs in a vCenter based on the inputs you provide.  
- This profile uses a custom InSpec vmware transport which must be installed by running "inspec plugin install /path/to/gem". The gem file is provided in this repo and is currently "train-vmware-0.2.0.gem"  
- The "VMware.PowerCLI" and "VMware.Vsphere.SsoAdmin" Powershell modules must be installed where this profile is being ran from.  
- When running the profile the custom vmware transport also connects to the sso admin server via "Connect-SsoAdminServer" and the credentials used to run the profile must also be an SSO admin.  

## vSphere InSpec Profiles

InSpec profiles for vSphere are available for each component or can be run all or some from the overlay profile. Note the overlay profile is setup to reference the other profiles from the same relative folder structure as seen here.  

[See the InSpec docs for more info on Profile dependencies and inheritance](https://www.inspec.io/docs/reference/profiles/)


## How to run InSpec locally from Powershell on Windows

**Note - assumes profile is downloaded to C:\Inspec\Profiles\vmware-vsphere-8.0-stig-baseline**  

It is recommended to utilize an inputs files for specifying environment specific variables.  

This profile uses the VMware train to execute PowerCLI commands.  As of the current release the best way to connect to a target vCenter is with environmental variables.  

For Windows from PowerShell setup the following variables for the existing session
```
$env:VISERVER="vcenter.test.local"
$env:VISERVER_USERNAME="Administrator@vsphere.local"
$env:VISERVER_PASSWORD="password"
```

Run all profiles against a target vCenter with needed inputs and output results to CLI  
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-8.0-stig-baseline -t vmware:// --input-file .\inputs-example.yml
```

Run all profiles against a target vCenter with needed inputs, show progress, and output results to CLI and JSON  
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-8.0-stig-baseline -t vmware:// --input-file .\inputs-example.yml --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json
```

Run a specific profile against a target vCenter show progress, and output results to CLI and JSON  
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-8.0-stig-baseline\esxi -t vmware:// --input-file .\inputs-example.yml --reporter=cli json:C:\Inspec\Reports\vcsa.json
```

Run a specific profile (EAM in this case) against a target vCenter show progress, and output results to CLI and JSON using the wrapper profile  
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-8.0-stig-baseline -t vmware:// --input-file .\inputs-example.yml --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json --controls=/VCEM/
```

Run a single STIG Control against a target vCenter  
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-8.0-stig-baseline -t vmware:// --input-file .\inputs-example.yml --controls=VCEM-80-000001
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
