# vmware-cloud-foundation-stig-baseline
VMware Cloud Foundation vSphere 9.0 STIG Readiness Guide Chef InSpec Profile    
Updated: 2025-06-17  
STIG Release: Y25M06  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance of the vSphere 9.x vCenter, ESX, and VM STIG controls. Does not include appliance level controls.  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine that has PowerCLI 13+ installed. Tested with version 6.8.24. Chef/CINC Workstation can also be installed and used.  
- If ran on a system with Powershell Core installed that is Version 7.2.1 or greater then run the following command first "$env:NO_COLOR=$true" . Newer versions of Powershell Core show ANSI escape characters differently and that causes issues with how the VMware train parses output.  
- Create an inputs file for your environment. See the inputs-example.yml file.  
- For ESX you can run it against a single host, all hosts in a cluster, or all hosts in a vCenter based on the inputs you provide.  
- For VMs you can run against a single VM or all VMs in a vCenter based on the inputs you provide.  
- This profile uses a custom InSpec vmware transport which must be installed by running "inspec plugin install /path/to/gem". The gem file is provided in this repo and is currently `train-vmware-1.0.0.gem`.  
- The `VMware.PowerCLI`, `VMware.Vsphere.SsoAdmin`, and `VMware.VCF.STIG.Helpers` Powershell modules must be installed where this profile is being ran from.  
- When running the profile the custom vmware transport also connects to the sso admin server via "Connect-SsoAdminServer" and the credentials used to run the profile must also be an SSO admin.  

## Supported Versions
- VCF 9.0.0.0  

## Inputs
Inputs for an InSpec profile are sometimes needed to provide environment specific values in order for tests to run correctly. These can be provided by specifying an inputs file with the target environments values.  

An example inputs file is provided with in the parent folder and can be found in the `inputs-example.yml` file. This file can be reused, copied, or modified as needed.  

Below is a list of inputs available for this profile that can be provided. 

### ESX Inputs
|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|`esx_vmhostName`   |`blank`                    |Specify an ESX hostname, cluster name, or all hosts to audit.|String|N/A|
|`esx_cluster`      |`blank`                    |Specify an ESX hostname, cluster name, or all hosts to audit.|String|N/A|
|`esx_allHosts`     |`false`                    |Specify an ESX hostname, cluster name, or all hosts to audit.|Boolean|N/A|
|`esx_adJoined`     |`false`                    |Set to true if ESX hosts are joined to Active Directory.|Boolean|VCFE-9X-000048|
|`esx_ntpServers`   |`[]`                       |Specify an array of NTP servers.|Array|VCFE-9X-000121|
|`esx_vmotionVlanId`|`blank`                    |Specify the VLAN used for vMotion.|String|VCFE-9X-000152|
|`esx_lockdownExceptionUsers`|`[]`              |Users allowed to bypass lockdown mode. Normally empty...use double quotes if including AD users with a /.|Array|VCFE-9X-000205|
|`esx_snmpEnabled`  |`false`                    |Is SNMP in use?.|String|VCFE-9X-000215|

### VM Inputs
|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|`vm_Name`          |`blank`                    |Specify a single VM name, a target vSphere cluster, or all VMs to audit.|String|N/A|
|`vm_cluster`       |`blank`                    |Specify a single VM name, a target vSphere cluster, or all VMs to audit.|String|N/A|
|`vm_allvms`        |`false`                    |Specify a single VM name, a target vSphere cluster, or all VMs to audit.|Boolean|N/A|

### vCenter Inputs
|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|`vcenter_ipfixCollectorAddresses`|`blank`      |If IpFix is used enter an array of collector addresses that are authorized.|String|VCFA-9X-000326|
|`vcenter_allowedTrunkingPortgroups`|`blank`    |If any portgroups are authorized to be configuring for trunking provide an array of portgroup names.|String|VCFA-9X-000327|
|`vcenter_bashShellAdminUsers`|`['Administrator']`|Array of authorized users that should be in the SystemConfiguration.BashShellAdministrators SSO group.|Array|VCFA-9X-000333|
|`vcenter_bashShellAdminGroups`|`[]`|Array of authorized groups that should be in the SystemConfiguration.BashShellAdministrators SSO group.|Array|VCFA-9X-000333|
|`vcenter_portMirrorSessions`|`[]`|Array of authorized port mirroring sessions by session name.|Array|VCFA-9X-000340|

## vSphere InSpec Profiles
InSpec profiles for vSphere are available for each component or can be run all or some from the overlay profile. Note the overlay profile is setup to reference the other profiles from the same relative folder structure as seen here.  
[See the InSpec docs for more info on Profile dependencies and inheritance](https://www.inspec.io/docs/reference/profiles/)

## Running InSpec/CINC-auditor

### Setup Connection to vCenter
This profile uses a custom VMware InSpec transport(train) to execute PowerCLI commands that must be installed in order for this profile to run. This custom transport is derived from the default InSpec VMware transport and extends it by adding support for the `VMware.Vsphere.SsoAdmin` Powershell module as well as an optional connection method using a Powershell credential file.  

Connection Options:  
  - Provide vCenter credentials via environment variables
  - Create a Powershell credential file and then provide the file name via an environment variable

#### Connecting via username/password
From a Powershell session create the following environment variables:
```
$env:VISERVER="vcenter.test.local"
$env:VISERVER_USERNAME="Administrator@vsphere.local"
$env:VISERVER_PASSWORD="password"
# For Powershell Core only
$env:NO_COLOR=$true
```

#### Connecting via a Powershell Credential file
From a Powershell session create a powershell credential file:
```
Set-vCenterCredentials -OutputFile credentialfile.xml
```
From a Powershell session create the following environment variables:
```
$env:VISERVER="vcenter.test.local"
$env:PCLICREDFILE="/full/path/to/credentialfile.xml"
# For Powershell Core only
$env:NO_COLOR=$true
```

**Note: If the `PCLICREDFILE` environment variable exists it will take precedence over username and password when attempting the connection to vCenter.**

### Prepare inputs file
Provide the target environments inputs values in the inputs file to be used for the scan.

### Running the audit
The example commands below can be adapted to different environments and different paths as needed. 

**NOTE** If using CINC instead of InSpec, replace the `inspec` command with `cinc-auditor` for the best experience.  

Run all profiles against a target vCenter, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI.  
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/vsphere -t vmware:// --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml
```

Run all profiles against a target vCenter, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI and JSON.  
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/vsphere -t vmware:// --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml --reporter=cli json:<path to report>.json
```

Run a specific profile (esx) against a target vCenter, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI and JSON.  
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/vsphere/esx -t vmware:// --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml --reporter=cli json:<path to report>.json
```

Run the profile against a target vCenter, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI but only audit a specific control.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/vsphere/esx -t vmware:// --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml --controls VCFE-9X-000005
```

Run all profiles against a target vCenter, show progress, enable enhanced outcomes, provide inputs via an inputs file specify a waiver file, and output results to the CLI.    
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/vsphere -t vmware:// --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml --waiver-file <path to>/waiver-example.yml
```

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into [MITRE's Heimdall](https://github.com/mitre/heimdall2) server for a more polished visual result.

## InSpec Vendoring
When a profile is ran, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.  

If any dependencies are added or updated that are in the `inspec.yml` file, run the `inspec vendor --overwrite` command to ensure the latest changes are used when running the profile.  
