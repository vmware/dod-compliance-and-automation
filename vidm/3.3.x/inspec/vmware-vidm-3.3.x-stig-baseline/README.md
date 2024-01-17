# vmware-vidm-3.3.x-stig-baseline
VMware Identity Manager 3.3.x STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 3 Date: 17 January 2024   
STIG Type: STIG Readiness Guide

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the VMware Identity Manager (Workspace ONE Access) 3.3.x STIG Readiness Guide.  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH target node. Tested with version 6.6.0. Chef/CINC Workstation can also be installed and used.
- Supported on vIDM 3.3.7.
- SSH access to vIDM appliances.
- Update the inputs in inspec-example.yml or make a new copy and update as appropriate for your environment

## Inputs
Inputs are used to provide variable information that customize how the profile is ran against the target system. Below is a list of inputs available for this profile that can be provided.  

|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|authprivlog        |/var/log/messages          |The expected log path for the authpriv log in the rsyslog config.|String|PHTN-30-000007|
|clustered          |false                      |Is the vIDM instance clustered? true or false|Boolean|N/A|

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
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --sudo --sudo-password 'password' --input-file .\inputs-example.yml
```

Run all profiles against a target appliance, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --show-progress --sudo --sudo-password 'password' --input-file .\inputs-example.yml --reporter=cli json:C:\Inspec\Reports\vidm.json
```

Run a specific profile against a target appliance show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --show-progress --sudo --sudo-password 'password' --input-file .\inputs-example.yml --reporter=cli json:C:\Inspec\Reports\vidm.json
```

Run a specific profile (vPostgres in this case) against a target appliance show progress, and output results to CLI and JSON using the wrapper profile
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --show-progress --sudo --sudo-password 'password' --input-file .\inputs-example.yml --reporter=cli json:C:\Inspec\Reports\vidm.json --controls=/WOAD/
```

Run a single STIG Control against a target appliance from a specific profile
```
inspec exec C:\Inspec\Profiles\vmware-vidm-3.3.x-stig-baseline -t ssh://root@vidm IP or FQDN --password 'password' --sudo --sudo-password 'password' --input-file .\inputs-example.yml --controls=WOAD-3X-000001
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
