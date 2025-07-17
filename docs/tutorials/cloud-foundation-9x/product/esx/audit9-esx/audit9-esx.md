# Audit ESX 9.0.0.0

## Overview
This tutorial covers auditing ESX hosts in VCF deployments.  


The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.


### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* InSpec/Cinc Auditor 6.8.24
* InSpec train-vmware 1.0.0
* SAF CLI 1.4.20
* STIG Viewer 2.17
* A VCF 9.0.0.0+ environment 
* PowerShell 7.4.7
* VCF PowerCLI 9.0.0.0+
* VCF STIG Helpers PowerShell module 1.0.1+

#### VCF STIG Helpers PowerShell Module
The VCF STIG Helpers PowerShell module provides additional supporting functions to the scripts provided here and for the vSphere InSpec profiles.  

The functions provided are: `Set-vCenterCredentials` `Get-vCenterCredentials` `Set-PowerCLICredential` `Get-PowerCLICredentialUsername` `Get-PowerCLICredentialPassword` `Write-Message` `Write-Header` `Test-PowerCLI` `Test-vCenter` `Test-ESX`

### Assumptions
* Commands are being run from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* CINC Auditor is used in lieu of InSpec. If InSpec is used replace `cinc-auditor` with `inspec` when running commands.

### Install the custom VMware transport for InSpec (Not needed for the STIG Tools Appliance)
To extend the functionality of the VMware transport that ships with InSpec a custom one has been created that also incorporates the `VMware.Vsphere.SsoAdmin` module to extend automation coverage to the vCenter SSO STIG controls.  

To install the plugin that is included with the `vmware-cloud-foundation-stig-baseline` profile, do the following:

# Install the custom train-vmware plugin. Update the path to the gem as needed. The command will be the same on Windows and Linux.
> cinc-auditor plugin install /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/train-vmware-1.0.0.gem

# To verify the installation
> cinc-auditor plugin list

┌────────────────────────────────────────┬─────────┬──────────────┬─────────┬────────────────────────────────────────────────────────────────────────┐
│              Plugin Name               │ Version │     Via      │ ApiVer  │                              Description                               │
├────────────────────────────────────────┼─────────┼──────────────┼─────────┼────────────────────────────────────────────────────────────────────────┤
│ inspec-compliance                      │ 6.8.24  │ core         │ 2       │ Plugin to perform operations with Chef Automate                        │
│ inspec-habitat                         │ 6.8.24  │ core         │ 2       │ Plugin to create/upload habitat package                                │
│ inspec-init                            │ 6.8.24  │ core         │ 2       │ Plugin for scaffolding profile, plugin or a resource                   │
│ inspec-license                         │ 6.8.24  │ core         │ 2       │ Plugin to list user licenses.                                          │
│ inspec-parallel                        │ 6.8.24  │ core         │ 2       │ Plugin to handle parallel InSpec scan operations over multiple targets │
│ inspec-plugin-manager-cli              │ 6.8.24  │ core         │ 2       │ CLI plugin for InSpec                                                  │
│ inspec-reporter-html2                  │ 6.8.24  │ core         │ 2       │ Improved HTML reporter plugin                                          │
│ inspec-reporter-json-min               │ 6.8.24  │ core         │ 2       │ Json-min json reporter plugin                                          │
│ inspec-reporter-junit                  │ 6.8.24  │ core         │ 2       │ JUnit XML reporter plugin                                              │
│ inspec-sign                            │ 6.8.24  │ core         │ 2       │                                                                        │
│ inspec-streaming-reporter-progress-bar │ 6.8.24  │ core         │ 2       │ Displays a real-time progress bar and control title as output          │
│ inspec-supermarket                     │ 6.8.24  │ core         │ 0       │                                                                        │
│ train-aws                              │ 0.2.41  │ gem (system) │ train-1 │ AWS API Transport for Train                                            │
│ train-habitat                          │ 0.2.22  │ gem (system) │ train-1 │ Habitat API Transport for Train                                        │
│ train-kubernetes                       │ 0.2.1   │ gem (system) │ train-1 │ Train Kubernetes                                                       │
│ train-vmware                           │ 1.0.0   │ gem (user)   │ train-1 │ Train Plugin for VMware PowerCLI                                       │
│ train-winrm                            │ 0.2.13  │ gem (system) │ train-1 │ Windows WinRM API Transport for Train                                  │
└────────────────────────────────────────┴─────────┴──────────────┴─────────┴────────────────────────────────────────────────────────────────────────┘
 17 plugin(s) total

**Note - Plugins are installed per user and must be installed as the user running InSpec.**

## Auditing ESX

`Export-Clixml` only exports encrypted credentials on Windows. On non-Windows operating systems such as macOS and Linux, credentials are exported as plain text stored as a Unicode character array. This provides some obfuscation but does not provide encryption.

### Setup Connection to vCenter
This profile uses a custom VMware InSpec transport(train) to run PowerCLI commands that must be installed in order for this profile to run. This custom transport is derived from the default InSpec VMware transport and extends it by adding support for the `VMware.Vsphere.SsoAdmin` PowerShell module as well as an optional connection method using a PowerShell credential file.  

Connection Options:  

  - Provide vCenter credentials via environment variables
    - Take care to clear the history and close the PowerShell session to avoid any credentials left in memory/history if using this option.
  - Create a PowerShell credential file and then provide the file name via an environment variable
    - For more information on exporting credentials to XML see [Export-Clixml](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml?view=powershell-7.5).

#### Connecting via username/password
From a PowerShell session create the following environment variables:
```powershell
#Enter PowerShell
pwsh

$env:VISERVER="vcenter.rainpole.local"
$env:VISERVER_USERNAME="Administrator@vsphere.local"
$env:VISERVER_PASSWORD="password"
# For PowerShell Core only
$env:NO_COLOR=$true
```
*Note: If the password includes a single tick (') it must be substituted with four ticks ('''') in order for it to be properly escaped all the way through the process.*

#### Connecting via a PowerShell Credential file
From a PowerShell session create a PowerShell credential file:

```
# Enter PowerShell
pwsh

# Navigate to the profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere

# Create a PowerShell credential file and provide a username and password with sufficient privileges to vCenter
Set-vCenterCredentials -OutputFile vcentercreds.xml

# Example output
PowerShell credential request
Enter the username and password for vCenter server ''.
These credentials will be stored securely at 'vcentercreds.xml'.
User: administrator@vsphere.local
Password for user administrator@vsphere.local: ********************

Credentials saved to: vcentercreds.xml

UserName                                        Password
--------                                        --------
administrator@vsphere.local System.Security.SecureString

# Update environment variables for connection
$env:VISERVER="vcenter.rainpole.local"
$env:PCLICREDFILE="/usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/vcentercreds.xml"

# For PowerShell Core only (Not needed on STIG Tools Appliance)
$env:NO_COLOR=$true
```

**Note: If the `PCLICREDFILE` environment variable exists it will take precedence over username and password when attempting the connection to vCenter.**

### Update profile inputs
Included in the `vmware-cloud-foundation-stig-baseline` profile is an example `inputs-example.yml` file with variables relevant to ESX.  This is used to provide InSpec with values specific to the environment being audited.

Update profile inputs for the target environment.

```
# Navigate to the InSpec profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere

# Edit the example inputs file or create a new one
vi inputs-example.yml

# Update the values to target the desired ESX hosts and environment specific details
# Choose whether to scan a single host, all hosts in a cluster, or all hosts in vCenter. Precedence is allHosts > cluster > single host if multiple values are provided.
esx_vmhostName: 'esx1.rainpole.local'
esx_cluster: ''
esx_allHosts: false
# Enter the environment specific time servers.
esx_ntpServers:
  - 'time-a-g.nist.gov'
  - 'time-b-g.nist.gov'
# Enter the environment specific vMotion VLAN Id.
esx_vmotionVlanId: '100'
# Enter an array of users that should be in the lockdown mode exceptions list.
esx_lockdownExceptionUsers: []
# If snmp is used in the environment change to true.
esx_snmpEnabled: 'false'
```

### Run the audit directly with InSpec
In this example a single ESX host attached to the target vCenter will be scanned, specifying an inputs file, enabling enhanced outcomes in InSpec, and outputting a report to the CLI and to a JSON file.  

```
# Navigate to the InSpec profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere

# Run the audit
cinc-auditor exec ./esx/ -t vmware:// --show-progress --enhanced-outcomes --input-file ./inputs-example.yml --reporter cli json:/tmp/reports/VCF_9_ESX_esx1_Report.json

# Shown below is the last part of the output at the CLI.
  ✔  VCFE-9X-000240: The ESX host must not automatically grant administrative permissions to Active Directory groups.
     ✔  PowerCLI Command: Get-VMHost -Name esx1.rainpole.local | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd | Select-Object -ExpandProperty Value stdout.strip is expected to cmp == "false"
  ✔  VCFE-9X-000241: The ESX host must not disable validation of users and groups.
     ✔  PowerCLI Command: Get-VMHost -Name esx1.rainpole.local | Get-AdvancedSetting -Name Config.HostAgent.plugins.vimsvc.authValidateInterval | Select-Object -ExpandProperty Value stdout.strip is expected to cmp <= 90
     ✔  PowerCLI Command: Get-VMHost -Name esx1.rainpole.local | Get-AdvancedSetting -Name Config.HostAgent.plugins.vimsvc.authValidateInterval | Select-Object -ExpandProperty Value stdout.strip is expected to cmp > 0

Profile Summary: 41 successful controls, 25 control failures, 2 controls not reviewed, 1 control not applicable, 0 controls have error
Test Summary: 55 successful, 59 failures, 5 skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

**Note: These steps are only valid if the audit was conducted against a single ESX host. For multiple hosts see the section below on using the InSpec runner script.**
### Update the target details in the metadata file
First update the target hostname, hostip, hostmac, and hostfqdn fields in the `saf_cli_hdf2ckl_metadata.json` metadata file

```
# Update the saf_cli_hdf2ckl_metadata.json file
vi /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/saf_cli_hdf2ckl_metadata.json

"hostname": "esx1.rainpole.local",
"hostip": "10.1.1.20",
"hostmac": "00:00:00:00:00:00",
"hostfqdn": "esx1.rainpole.local",
```

### Run SAF CLI to create the CKL file
The following command will convert the json result from the InSpec audit into a STIG Checklist file and ensure the correct metadata is inserted so that it displays correctly in STIG Viewer.  

```
# Convert the InSpec report to a STIG Checklist
saf convert hdf2ckl -i /tmp/reports/VCF_9_ESX_esx1_Report.json -o /tmp/reports/VCF_9_ESX_esx1_Report.ckl -m /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/saf_cli_hdf2ckl_metadata.json
```

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  
![STIG Viewer Checklist](../../../images/esx_audit9_ckl_screenshot.png)

## Auditing ESX hosts in bulk
For accreditation purposes there may be a requirement to produce a CKL file for each ESX host and/or VM. To support this use case a PowerCLI script has been created that acts as a runner for InSpec to loop through a list of hosts or VMs, then produce a json report for each, and if the SAF CLI is installed also create a CKL file.  

With this script an [attestation](/docs/automation-tools/safcli/#creating-and-applying-manual-attestations) file can also be provided that will be applied to the results and incorporated into the CKL file.

### Prerequisites
* Authentication configured for vCenter. See previous section for details.
* The `VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner.ps1` script.

### Using the ESX runner script
To use the runner script, do the following:

```
# Enter PowerShell
pwsh

# Navigate to the powercli folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/powercli/vmware-cloud-foundation-stig-powercli-hardening

# Update the Global Variables file to specify the vCenter server and ESX targets of the script. Either an individual host or a target cluster.
vi VMware_Cloud_Foundation_vSphere_9.0_STIG_Global_Variables.ps1

$vcenter = "vcenter.rainpole.local"
$hostname = ""
$cluster = "cluster1"

# Create a PowerShell credential for the script to connect to vCenter. This is not used for the InSpec audit.
$vccred = Get-Credential

PowerShell credential request
Enter the credentials.
User: administrator@vsphere.local
Password for user administrator@vsphere.local: ********************

# Update the InSpec inputs file if needed and not done previously.
vi /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml

# Run the script without an attestation file and generate a STIG Checklist for each ESX host in the cluster.
./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner -vccred $vccred -InspecPath /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/esx/ -InspecInputsFile /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml

[2025-05-13 21:36:09] [INFO] Running InSpec against ESX host: esx1.rainpole.local.
Redirecting to cinc-auditor...
FFF.F.FF....FFF.F..FF..F.*.*.FFF.F...F....*.FFFF............FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF..........F...FF**....FFF...
[2025-05-13 21:37:19] [INFO] Detected MITRE SAF CLI. Generating STIG Viewer Checklist for ESX host: esx1.rainpole.local
[2025-05-13 21:37:20] [INFO] Attestation file not detected. Generating STIG Viewer Checklist for ESX host: esx1.rainpole.local without attestations.
[2025-05-13 21:37:20] [INFO] Generating CKL file: /tmp/reports/VMware_Cloud_Foundation_vSphere_ESX_9.x_STIG_InSpec_Report_esx1.rainpole.local_2025-5-13-21-33-43.ckl for ESX host: esx1.rainpole.local

# Run the script with an attestation file and generate a STIG Checklist for each ESX host in the cluster.
./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner -vccred $vccred -InspecPath /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/esx/ -InspecInputsFile /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/vsphere/inputs-example.yml -AttestationFile ./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner_Attestations_Example.yml

[2025-05-13 21:36:09] [INFO] Running InSpec against ESX host: esx1.rainpole.local.
Redirecting to cinc-auditor...
FFF.F.FF....FFF.F..FF..F.*.*.FFF.F...F....*.FFFF............FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF..........F...FF**....FFF...
[2025-05-13 21:37:19] [INFO] Detected MITRE SAF CLI. Generating STIG Viewer Checklist for ESX host: esx1.rainpole.local
[2025-05-13 21:50:16] [INFO] Attestation file: ./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner_Attestations_Example.yml detected. Applying to results for ESX host: esx1.rainpole.local
[2025-05-13 21:50:19] [INFO] Generating CKL file: /tmp/reports/VMware_Cloud_Foundation_vSphere_ESX_9.x_STIG_InSpec_Report_esx1.rainpole.local_with_Attestations_2025-5-13-21-49-2.ckl with attestations for ESX host: esx1.rainpole.local.internal
```

**Note: Not all options for the script are shown. For more details run `Get-Help ./VMware_Cloud_Foundation_vSphere_ESX_9.0_STIG_InSpec_Runner.ps1 -Detailed`.**

## Manually audit rules
The following rules require manual auditing and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFE-9X-000232`     |The ESX host must not be configured to override virtual machine (VM) configurations.                                                     |
| `VCFE-9X-000233`     |The ESX host must not be configured to override virtual machine (VM) logger settings.                                                    |

## Next
If needed proceed to the remediation tutorial for ESX [here](/docs/tutorials/cloud-foundation-9.x/product/esx/remediate9-esx/).
