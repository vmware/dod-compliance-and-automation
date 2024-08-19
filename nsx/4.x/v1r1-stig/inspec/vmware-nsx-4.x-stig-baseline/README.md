# vmware-nsx-4.x-stig-baseline
VMware NSX 4.x STIG Chef InSpec Profile  
Version: Release 1 Version 1 Date: 07 August 2024  
STIG Type: Official STIG   
Maintainers: Broadcom  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the NSX 4.x STIG.  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that has network access to the NSX Managers. Tested with version 6.6.0. Chef/CINC Workstation can also be installed and used.
- Administrative access to the target
- Create an inputs file for your environment. See the inputs-example.yml file. 
- An API token and session id cookie is needed for the tests to make API calls. Specify it on the command line or in the inputs file.  See https://developer.vmware.com/apis/1248/nsx-t for more details.  
- This profile uses the local transport to run API calls against an NSX Manager deployment.

## Inputs
Inputs are used to provide variable information that customize how the profile is ran against the target system. Below is a list of inputs available for this profile that can be provided.  

|     Input Name       |       Default Value       | Description |     Type    |   STIG IDs  |
|----------------------|---------------------------|-------------|-------------|-------------|
|nsxManager            |None                       |Target NSX Manager IP or FQDN.|String|All|
|sessionToken          |None                       |Session token generated for access to NSX.|Boolean|All|
|sessionCookieId       |None                       |Session cookie id generated for access to NSX. Example 'JSESSIONID=2A165FCF851CA50FCD038DFC8E770038'|String|All|
|ntpServers            |time-a-g.nist.gov,time-b-g.nist.gov|A list of NTP servers with which the system should sync.|Array|NMGR-4X-000067|
|syslogServers         |loginsight.test.com        |A list of Syslog servers with which the system should forward logs.|Array|NMGR-4X-000087,NT0F-4X-000020,NT1F-4X-000020|
|authorizedPermissions |See inputs example file    |A list of authorized users and their roles to validate assigned permissions in NSX. The default local users and their roles are provided as an example. This currently only validates roles assigned to all of NSX and not to Projects or other scopes.|Hash|NMGR-4X-000010|
|nsxtVersion           |4.2.0.0                    |Enter latest NSX version. Example '4.1.2.1'.|String|NMGR-4X-000096|
|t0multicastlist       |[]                         |Enter an array of T0 Gateway names that are approved to have multicast enabled.|Array|NT0R-4X-000013,NT0R-4X-000107|
|t0mcinterfacelist     |[]                         |Enter an array of T0 Gateway interface names that are approved to have multicast enabled.|Array|NT0R-4X-000013|
|t0dhcplist            |[]                         |Enter an array of T0 Gateway names that are approved to have DHCP enabled.|Array|NT0R-4X-000027|
|t1dhcplist            |[]                         |Enter an array of T1 Gateway names that are approved to have DHCP enabled.|Array|NT1R-4X-000027|
|t1multicastlist       |[]                         |Enter an array of T1 Gateway names that are approved to have multicast enabled.|Array|NT1R-4X-000107|

## Running the profile

#### Run all controls in the profile against a target deployment and specify inputs with an inputs file
```
inspec exec <Profile> --show-progress --input-file=inputs-nsx-4.x-example.yml
```

#### Run all profiles against a target deployment with example inputs, show progress, and output results to CLI and JSON
```
inspec exec <Profile> --show-progress --input-file=inputs-nsx-4.x-example.yml --reporter=cli json:path\to\report\report.json
```

#### Run a single STIG Control against a target deployment
```
inspec exec <Profile> --input-file=inputs-nsx-4.x-example.yml --controls=T0FW-4X-000002
```

#### Run all controls in the profile against a target appliance and specify a waiver file 
```
inspec exec <Profile> --input-file=inputs-nsx-4.x-example.yml --show-progress --waiver-file <waiverfile.yml>
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
