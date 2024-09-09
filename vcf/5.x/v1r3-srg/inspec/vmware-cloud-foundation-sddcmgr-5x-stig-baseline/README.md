# vmware-cloud-foundation-sddcmgr-5x-stig-baseline
VMware Cloud Foundation SDDC Manager 5.x STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 3 Date: 23 July 2024  
STIG Type: STIG Readiness Guide

## SDDC Manager InSpec Profiles
InSpec profiles for the SDDC Manager are available for each component or can be run all or some from the wrapper/overlay profile. Note the wrapper profile is setup to reference the other profiles from the same relative folder structure as seen here.  

[See the InSpec docs for more info on Profile dependencies and inheritance](https://www.inspec.io/docs/reference/profiles/)

## Supported Versions
- VCF 5.2  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that can SSH to the target. Tested with version 6.6.0. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target via root or sudo
- Update the values in the inputs file example as appropriate for your environment
- Allowing root ssh may be required in order to run the profile since the vcf user cannot sudo. Remember to turn it back off afterwards.**
- An API bearer token is needed for the SDDC Manager Application controls to make API calls. Specify it on the command line or in the inputs file.** 
- The bearer token can be generated with the `/v1/tokens` API call or in the UI through the developer center.**  

## Inputs
Inputs are used to provide variable information that customize how the profile is ran against the target system. Below is a list of inputs available for this profile that can be provided.  

### Default Input Values
|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|`bearerToken`      |`Bearer eyJhbGciOiJIUzI1NiJ9.ey...`|Bearer token used for authentication to audit application rules.|String|CFAP|
|`sddcManager`      |`sddc-manager.sfo01.rainpole.local`|IP or FQDN of SDDC Manager.|String|CFAP|
|`sftpBackupsEnabled`|`true`                            |Set to true if SFTP backups are used for SDDC Manager or false if image based backups are used.|Boolean|CFAP-5X-000035|
|`sftpServer`       |`10.0.0.1`                         |Enter SFTP backup server name or ip. This should not be the SDDC Manager itself!|String|CFAP-5X-000035|
|`ntpServers`       |`['time-a-g.nist.gov','time-b-g.nist.gov']`|Enter one or more NTP servers in an array format.|Array|CFAP-5X-000084|
|`currentVersion`   |`true`                             |Enter the latest version for SDDC Manager.|String|CFAP-5X-000113|
|`myVmwareAccount`  |`myvmwarevcfaccount@test.local`    |Enter the account name for the My VMware account configured to pull updates online if used. Leave blank if updates are downloaded offline.|String|CFAP-5X-000126|

## How to run InSpec locally from Powershell on Windows

**Note - assumes profile is downloaded to C:\Inspec\Profiles\vmware-vsphere-8.0-stig-baseline**  

Run all profiles against a target appliance with needed inputs and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-cloud-foundation-sddcmgr-5x-stig-baseline -t ssh://root@IP or FQDN --password 'password' --input syslogServer=test.local:514
```

Run all profiles against a target appliance with needed inputs, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-cloud-foundation-sddcmgr-5x-stig-baseline -t ssh://root@IP or FQDN --password 'password' --input syslogServer=test.local:514 ntpServer1=time.test.local ntpServer2=time2.test.local --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json
```

Run a specific profile against a target appliance show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-cloud-foundation-sddcmgr-5x-stig-baseline\commonsvcs -t ssh://root@IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vcf.json
```

Run a specific profile against a target appliance show progress, and output results to CLI and JSON using the wrapper profile
```
inspec exec C:\Inspec\Profiles\vmware-cloud-foundation-sddcmgr-5x-stig-baseline -t ssh://root@IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vcf.json --controls=/CFCS/
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
