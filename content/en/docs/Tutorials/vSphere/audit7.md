---
title: "Audit vSphere 7"
weight: 1
description: >
  Auditing vSphere 7 for STIG Compliance
---
## Overview
Auditing vSphere for STIG compliance involves scanning ESXi, Virtual Machines, vCenter, and the vCenter appliance.

When auditing vSphere we will split up tasks between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration effecting availability of the product is low but could impact how the environment is operated if not assessed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc) that make up the product. Altering these add risk to product availability without precautionary steps and care in implementation. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

To audit vSphere using InSpec we utilize the VMware transport(train-vmware) which connects to vCenter via PowerCLI and performs queries. For the vCenter appliance the auditing is performed via SSH. It is recommended to disable SSH on vCenter after the auditing is complete.  

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vmware-vsphere-7.0-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vsphere/inspec/vmware-vsphere-7.0-stig-baseline) profile downloaded.
* The [vmware-vcsa-7.0-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vcsa/inspec/vmware-vcsa-7.0-stig-baseline) profile downloaded.
* Powershell 7.3.4/PowerCLI 13.1
* [VMware.Vsphere.SsoAdmin PowerCLI Module 1.3.9](https://www.powershellgallery.com/packages/VMware.vSphere.SsoAdmin)
* InSpec/Cinc Auditor 5.22.3
* train-vmware 0.2.0
* SAF CLI 1.2.11
* STIG Viewer 2.17
* A vSphere 7.x environment. 7.0 U3l was used in these examples.
* An account with sufficient privileges to view SSO configuration in vCenter.
* Example distributed switches, VMs, and a content library were created in the testbed to produce audit results for those objects.  

### Install the custom VMware transport for InSpec
To extend the functionality of the VMware transport that ships with InSpec we have created a custom one that also incorporates the `VMware.Vsphere.SsoAdmin` module to extend automation coverage to the vCenter SSO STIG controls.  

To install the plugin that is included with the `vmware-vsphere-7.0-stig-baseline` profile, do the following:
```powershell
# Install the custom train-vmware plugin. Update the path to the gem as needed. The command will be the same on Windows and Linux.
> inspec plugin install C:\vmware-vsphere-7.0-stig-baseline\train-vmware-0.2.0.gem

# To verify the installation
> inspec plugin list

┌────────────────────────────────────────┬─────────┬──────────────┬─────────┬───────────────────────────────────────────────────────────────┐
│              Plugin Name               │ Version │     Via      │ ApiVer  │                          Description                          │
├────────────────────────────────────────┼─────────┼──────────────┼─────────┼───────────────────────────────────────────────────────────────┤
│ inspec-compliance                      │ 5.22.3  │ core         │ 2       │ Plugin to perform operations with Chef Automate               │
│ inspec-habitat                         │ 5.22.3  │ core         │ 2       │ Plugin to create/upload habitat package                       │
│ inspec-init                            │ 5.22.3  │ core         │ 2       │ Plugin for scaffolding profile, plugin or a resource          │
│ inspec-plugin-manager-cli              │ 5.22.3  │ core         │ 2       │ CLI plugin for InSpec                                         │
│ inspec-reporter-html2                  │ 5.22.3  │ core         │ 2       │ Improved HTML reporter plugin                                 │
│ inspec-reporter-json-min               │ 5.22.3  │ core         │ 2       │ Json-min json reporter plugin                                 │
│ inspec-reporter-junit                  │ 5.22.3  │ core         │ 2       │ JUnit XML reporter plugin                                     │
│ inspec-sign                            │ 5.22.3  │ core         │ 2       │                                                               │
│ inspec-streaming-reporter-progress-bar │ 5.22.3  │ core         │ 2       │ Displays a real-time progress bar and control title as output │
│ inspec-supermarket                     │ 5.22.3  │ core         │ 0       │                                                               │
│ train-aws                              │ 0.2.24  │ gem (system) │ train-1 │ AWS API Transport for Train                                   │
│ train-habitat                          │ 0.2.22  │ gem (system) │ train-1 │ Habitat API Transport for Train                               │
│ train-kubernetes                       │ 0.1.12  │ gem (system) │ train-1 │ Train Kubernetes                                              │
│ train-vmware                           │ 0.2.0   │ gem (user)   │ train-1 │ Train Plugin for VMware PowerCLI                              │
│ train-winrm                            │ 0.2.13  │ gem (system) │ train-1 │ Windows WinRM API Transport for Train                         │
└────────────────────────────────────────┴─────────┴──────────────┴─────────┴───────────────────────────────────────────────────────────────┘
 15 plugin(s) total
 ```

## Auditing ESXi Hosts
### Update profile inputs
Included in the `vmware-vsphere-7.0-stig-baseline` is an example [inputs-example.yml](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/inspec/vmware-vsphere-7.0-stig-baseline/inputs-example.yml) file with the following inputs relevant to ESXi.

Update the inputs as shown below with values relevant to your environment.
```yaml
# Choose whether to scan a single host, all hosts in a cluster, or all hosts in vCenter.
vmhostName: ""
cluster: ""
allesxi: true
# Enter an array of users that should be in the lockdown mode exceptions list.
exceptionUsers: []
# Enter the environment specific syslog server ESXi should be forwarding logs to.
syslogServer: "tcp://log.test.local:514"
# If ESXi is joined to AD, enter the AD group that has administrative access to ESXi.
adAdminGroup: "MyAdAdminGroup"
# Enter the environment specific time servers.
esxiNtpServers:
  - 'time-a-g.nist.gov'
  - 'time-b-g.nist.gov'
# Enter the environment specific vMotion VLAN Id.
vMotionVlanId: "100"
# Enter the environment specific Management VLAN Id.
mgtVlanId: "101"
# If snmp is used in the environment change to true.
snmpEnabled: "false"
# Enter the latest build number for ESXi.
esxiBuildNumber: "21424296"
```

### Setup environment variables for vCenter connection
Connectivity to vCenter is established via environment variables. Take care to clear your history and close the Powershell session to avoid any credentials left in memory/history.
```powershell
# Note: VISERVER is referencing vCenter and not an ESXi host.
> $env:VISERVER="10.182.131.166"
> $env:VISERVER_USERNAME="Administrator@vsphere.local"
> $env:VISERVER_PASSWORD="password"
```

### Run the audit
In this example we will be scanning all ESXi hosts attached to the target vCenter, specifying an inputs file, enabling enhanced outcomes in InSpec, and outputting a report to the CLI and to a JSON file.  
```powershell
# Note this command is being ran from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec .\esxi\ -t vmware:// --show-progress --input-file .\inputs-example.yml --enhanced-outcomes --reporter=cli json:C:\InSpec\Reports\MyESXiReport.json

# Shown below is the last part of the output at the CLI.
  [FAIL]  ESXI-70-000097: The ESXi Common Information Model (CIM) service must be disabled. (2 failed)
     [FAIL]  PowerCLI Command: Get-VMHost -Name 10.182.131.186 | Get-VMHostService | Where {$_.Label -eq 'CIM Server'} | Select-Object -ExpandProperty Policy stdout.strip is expected to cmp == "off"

     expected: off
          got: on

     (compared using `cmp` matcher)

     [PASS]  PowerCLI Command: Get-VMHost -Name 10.182.131.186 | Get-VMHostService | Where {$_.Label -eq 'CIM Server'} | Select-Object -ExpandProperty Running stdout.strip is expected to cmp == "false"
     [FAIL]  PowerCLI Command: Get-VMHost -Name 10.182.132.6 | Get-VMHostService | Where {$_.Label -eq 'CIM Server'} | Select-Object -ExpandProperty Policy stdout.strip is expected to cmp == "off"

     expected: off
          got: on

     (compared using `cmp` matcher)

     [PASS]  PowerCLI Command: Get-VMHost -Name 10.182.132.6 | Get-VMHostService | Where {$_.Label -eq 'CIM Server'} | Select-Object -ExpandProperty Running stdout.strip is expected to cmp == "false"
     [PASS]  PowerCLI Command: Get-VMHost -Name 10.182.138.1 | Get-VMHostService | Where {$_.Label -eq 'CIM Server'} | Select-Object -ExpandProperty Policy stdout.strip is expected to cmp == "off"
     [PASS]  PowerCLI Command: Get-VMHost -Name 10.182.138.1 | Get-VMHostService | Where {$_.Label -eq 'CIM Server'} | Select-Object -ExpandProperty Running stdout.strip is expected to cmp == "false"
  [N/R]  ESXI-70-000274: The ESXi host SSH daemon must be configured to only use FIPS 140-2 validated ciphers.
     [SKIP]  This must be reviewed manually

Profile Summary: 25 successful controls, 27 control failures, 20 controls not reviewed, 3 controls not applicable, 0 controls have error
Test Summary: 143 successful, 120 failures, 34 skipped
```

## Auditing Virtual Machines
### Update profile inputs
Included in the `vmware-vsphere-7.0-stig-baseline` is an example [inputs-example.yml](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/inspec/vmware-vsphere-7.0-stig-baseline/inputs-example.yml) file with the following inputs relevant to VMs.

Update the inputs as shown below with values relevant to your environment.
```yaml
# Choose whether to scan a single VM or all VMs in vCenter.
vmName: ""
allvms: true
```

### Setup environment variables for vCenter connection
Connectivity to vCenter is established via environment variables. Take care to clear your history and close the Powershell session to avoid any credentials left in memory/history.

If was done in the previous step it is not necessary to do again.
```powershell
# Note: VISERVER is referencing vCenter and not an ESXi host.
> $env:VISERVER="10.182.131.166"
> $env:VISERVER_USERNAME="Administrator@vsphere.local"
> $env:VISERVER_PASSWORD="password"
```

### Run the audit
In this example we will be scanning all VMs in the target vCenter, specifying an inputs file, enabling enhanced outcomes in InSpec, and outputting a report to the CLI and to a JSON file.  
```powershell
# Note this command is being ran from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec .\vm\ -t vmware:// --show-progress --input-file .\inputs-example.yml --enhanced-outcomes --reporter=cli json:C:\InSpec\Reports\MyVMsReport.json

# Shown below is the last part of the output at the CLI.
  [FAIL]  VMCH-70-000027: Log retention must be configured properly on the virtual machine (VM). (2 failed)
     [FAIL]  PowerCLI Command: Get-VM -Name 'stig space test' | Get-AdvancedSetting -Name log.keepOld | Select-Object -ExpandProperty Value stdout.strip is expected to cmp == "10"

     expected: 10
          got:

     (compared using `cmp` matcher)

     [FAIL]  PowerCLI Command: Get-VM -Name 'stigvmtest1' | Get-AdvancedSetting -Name log.keepOld | Select-Object -ExpandProperty Value stdout.strip is expected to cmp == "10"

     expected: 10
          got:

     (compared using `cmp` matcher)

     [PASS]  PowerCLI Command: Get-VM -Name 'vCLS-189ef61c-56dc-4d5f-a255-ac43798a77b3' | Get-AdvancedSetting -Name log.keepOld | Select-Object -ExpandProperty Value stdout.strip is expected to cmp == "10"
     [PASS]  PowerCLI Command: Get-VM -Name 'vCLS-6e74013e-53a1-4589-a2f7-47f11674d089' | Get-AdvancedSetting -Name log.keepOld | Select-Object -ExpandProperty Value stdout.strip is expected to cmp == "10"
     [PASS]  PowerCLI Command: Get-VM -Name 'vCLS-d7018f26-8dab-48c7-8161-56311f5eb077' | Get-AdvancedSetting -Name log.keepOld | Select-Object -ExpandProperty Value stdout.strip is expected to cmp == "10"
  [PASS]  VMCH-70-000028: DirectPath I/O must be disabled on the virtual machine (VM) when not required.
     [PASS]  PowerCLI Command: Get-VM -Name 'stig space test' | Get-AdvancedSetting -Name pciPassthru*.present | Select-Object -ExpandProperty Value stdout.strip is expected to be empty
     [PASS]  PowerCLI Command: Get-VM -Name 'stigvmtest1' | Get-AdvancedSetting -Name pciPassthru*.present | Select-Object -ExpandProperty Value stdout.strip is expected to be empty
     [PASS]  PowerCLI Command: Get-VM -Name 'vCLS-189ef61c-56dc-4d5f-a255-ac43798a77b3' | Get-AdvancedSetting -Name pciPassthru*.present | Select-Object -ExpandProperty Value stdout.strip is expected to be empty
     [PASS]  PowerCLI Command: Get-VM -Name 'vCLS-6e74013e-53a1-4589-a2f7-47f11674d089' | Get-AdvancedSetting -Name pciPassthru*.present | Select-Object -ExpandProperty Value stdout.strip is expected to be empty
     [PASS]  PowerCLI Command: Get-VM -Name 'vCLS-d7018f26-8dab-48c7-8161-56311f5eb077' | Get-AdvancedSetting -Name pciPassthru*.present | Select-Object -ExpandProperty Value stdout.strip is expected to be empty
  [PASS]  VMCH-70-000029: Encryption must be enabled for Fault Tolerance on the virtual machine (VM).
     [PASS]  PowerCLI Command: (Get-VM -Name 'stig space test').ExtensionData.Config.FtEncryptionMode stdout.strip is expected to be in "ftEncryptionOpportunistic" and "ftEncryptionRequired"
     [PASS]  PowerCLI Command: (Get-VM -Name 'stigvmtest1').ExtensionData.Config.FtEncryptionMode stdout.strip is expected to be in "ftEncryptionOpportunistic" and "ftEncryptionRequired"
     [PASS]  PowerCLI Command: (Get-VM -Name 'vCLS-189ef61c-56dc-4d5f-a255-ac43798a77b3').ExtensionData.Config.FtEncryptionMode stdout.strip is expected to be in "ftEncryptionOpportunistic" and "ftEncryptionRequired"
     [PASS]  PowerCLI Command: (Get-VM -Name 'vCLS-6e74013e-53a1-4589-a2f7-47f11674d089').ExtensionData.Config.FtEncryptionMode stdout.strip is expected to be in "ftEncryptionOpportunistic" and "ftEncryptionRequired"
     [PASS]  PowerCLI Command: (Get-VM -Name 'vCLS-d7018f26-8dab-48c7-8161-56311f5eb077').ExtensionData.Config.FtEncryptionMode stdout.strip is expected to be in "ftEncryptionOpportunistic" and "ftEncryptionRequired"

Profile Summary: 11 successful controls, 15 control failures, 2 controls not reviewed, 0 controls not applicable, 0 controls have error
Test Summary: 75 successful, 55 failures, 2 skipped
```

## Auditing vCenter (Product Controls)
### Update profile inputs
Included in the `vmware-vsphere-7.0-stig-baseline` is an example [inputs-example.yml](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/inspec/vmware-vsphere-7.0-stig-baseline/inputs-example.yml) file with the following inputs relevant to vCenter.

Update the inputs as shown below with values relevant to your environment.
```yaml
# Enter the environment specific syslog server vCenter should be forwarding logs to.
syslogServers:
  - "loginsight.test.com"
  - "syslog.server2.com"
# Enter the environment specific time servers.
ntpServers:
  - 'time-a-g.nist.gov'
  - 'time-b-g.nist.gov'
# If an IPfix collector is used enter the IP.
ipfixCollectorAddress: ""
# Enter any approved users in the bash shell administrators users group
bashShellAdminUsers:
  - 'Administrator'
# Enter any approved group in the bash shell administrators group
bashShellAdminGroups: []
# Enter any approved users in the trusted admin users group
trustedAdminUsers: []
# Enter any approved users in the trusted admin group
trustedAdminGroups: []
# Set to false if file based backups are used via the VAMI
backup3rdParty: false
```

### Setup environment variables for vCenter connection
Connectivity to vCenter is established via environment variables. Take care to clear your history and close the Powershell session to avoid any credentials left in memory/history.

If was done in the previous step it is not necessary to do again.
```powershell
# Note: VISERVER is referencing vCenter and not an ESXi host.
> $env:VISERVER="10.182.131.166"
> $env:VISERVER_USERNAME="Administrator@vsphere.local"
> $env:VISERVER_PASSWORD="password"
```

### Run the audit
In this example we will be scanning vCenter controls in the target vCenter, specifying an inputs file, enabling enhanced outcomes in InSpec, and outputting a report to the CLI and to a JSON file.  
```powershell
# Note this command is being ran from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec .\vcenter\ -t vmware:// --show-progress --input-file .\inputs-example.yml --enhanced-outcomes --reporter=cli json:C:\InSpec\Reports\MyvCenterReport.json

# Shown below is the last part of the output at the CLI.
  [PASS]  VCSA-70-000291: The vCenter Server must limit membership to the "TrustedAdmins" Single Sign-On (SSO) group.
     [PASS]  Stderr should be empty if no users found is expected to be empty
     [PASS]  No users found in TrustedAdmins is expected to be empty
     [PASS]  Stderr should be empty if no groups found is expected to be empty
     [PASS]  No groups found in TrustedAdmins is expected to be empty
  [FAIL]  VCSA-70-000292: The vCenter server configuration must be backed up on a regular basis.
     [FAIL]  File based backups should be enabled. is expected to cmp == "true"

     expected: true
          got:

     (compared using `cmp` matcher)

  [PASS]  VCSA-70-000293: vCenter task and event retention must be set to at least 30 days.
     [PASS]  PowerCLI Command: Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name event.maxAge | Select-Object -ExpandProperty Value stdout.strip is expected to cmp == "30"
     [PASS]  PowerCLI Command: Get-AdvancedSetting -Entity $global:DefaultViServers.Name -Name task.maxAge | Select-Object -ExpandProperty Value stdout.strip is expected to cmp == "30"
  [N/R]  VCSA-70-000294: vCenter Native Key Providers must be backed up with a strong password.
     [SKIP]  This must be reviewed manually

Profile Summary: 19 successful controls, 16 control failures, 22 controls not reviewed, 0 controls not applicable, 0 controls have error
Test Summary: 52 successful, 19 failures, 22 skipped
```

## Run a combined scan for all vSphere product controls
Instead of running each STIG for product controls separately you can also run all of the vCenter, ESXi, and VM controls for a combined report.

```powershell
# Note this command is being ran from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec . -t vmware:// --show-progress --input-file .\inputs-example.yml --reporter=cli json:C:\InSpec\Reports\MyvSphereReport.json
```

## Using the InSpec runner script
For accredidation purposes there may be a requirement to produce a CKL file for each ESXi host and/or VM.  

We have also created a PowerCLI script that acts as a runner for InSpec to loop through a list of hosts or VMs and then produce a json report for each and if the SAF CLI is installed also create a CKL file. 

Currently we have an example for doing this with ESXi hosts available [here](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/powercli/VMware_vSphere_7.0_STIG_ESXi_InSpec_Runner.ps1).

With this script you can also provide an [attestation](/docs/automation-tools/safcli/#creating-and-applying-manual-attestations) file that will be applied to the results and incorporated into the CKL file.

To use the runner script, do the following:
```powershell
# If not done already provide the credentials for InSpec to connect to vCenter.
# Note: VISERVER is referencing vCenter and not an ESXi host.
> $env:VISERVER="10.182.131.166"
> $env:VISERVER_USERNAME="Administrator@vsphere.local"
> $env:VISERVER_PASSWORD="password"
# Adjust the paths in the command as needed. The inspec and inputs paths in the example are assuming this is being ran from the root of the InSpec profile folder.
> C:\github\VMware_vSphere_7.0_STIG_ESXi_InSpec_Runner.ps1 -vcenter 10.182.131.166 -reportPath C:\Inspec\Reports\Runner -inspecPath .\esxi\ -inputsfile .\inputs-example.yml

# You will be prompted for credentials to vCenter. This is to connect via PowerCLI before running InSpec to collect all of the host names to use as an input to InSpec for each individual host audit.
8:48:29 AM ...Enter credentials to connect to vCenter

PowerShell credential request
Enter credentials for vCenter
User: administrator@vsphere.local
Password for user administrator@vsphere.local: ****************

8:48:44 AM ...Connecting to vCenter Server 10.182.131.166
8:48:47 AM ...Getting PowerCLI objects for all ESXi hosts in vCenter: 10.182.131.166
8:48:48 AM ...Validated path for report at C:\Inspec\Reports\Runner
8:48:48 AM ...Report path is C:\Inspec\Reports\Runner and report file is C:\Inspec\Reports\Runner\VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.131.186-5-19-2023_8-48-29.json
8:48:48 AM ...Running InSpec exec against 10.182.131.186 with inspec exec $inspecPath -t vmware:// --input vmhostName=$name --input-file $inputsFile --show-progress --reporter=json:$reportFile
FFF......FFFFF....FFFF.FFFF.*...***********...FF.FF.....F.F..FFFF..FFF***FFFF.FFF.FF.FF....FFFFFF..F...***FF*FF*FF**...***...FFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFFFFFF.FFFFF...................FF....FF...............................*......*FFF......*......F..FF..F....FF.***FF....FF....FF.**FFFFFFF.F...*
8:51:49 AM ...Detected saf cli...generating STIG Viewer Checklist for 10.182.131.186
8:51:53 AM ...Report path is C:\Inspec\Reports\Runner and report file is C:\Inspec\Reports\Runner\VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.132.6-5-19-2023_8-48-29.json
8:51:53 AM ...Running InSpec exec against 10.182.132.6 with inspec exec $inspecPath -t vmware:// --input vmhostName=$name --input-file $inputsFile --show-progress --reporter=json:$reportFile
FFF......FFFFF....FFFF.FFFF.*...***********...FF.FF.....F.F..FFFF..FFF***FFFF.FFF.FF.FF....FFFFFF..F...***FF*FF*FF**...***...FFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFFFFFF.FFFFF...................FF....FF...............................*......*FFF......*......F..FF..F....FF.***FF....FF....FF.**FFFFFFF.F...*
8:54:54 AM ...Detected saf cli...generating STIG Viewer Checklist for 10.182.132.6
8:54:59 AM ...Report path is C:\Inspec\Reports\Runner and report file is C:\Inspec\Reports\Runner\VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.138.1-5-19-2023_8-48-29.json
8:54:59 AM ...Running InSpec exec against 10.182.138.1 with inspec exec $inspecPath -t vmware:// --input vmhostName=$name --input-file $inputsFile --show-progress --reporter=json:$reportFile
FFF......FFFFF....FFFF.FFFF.*...***********...FF.FF.....F.F..FFFF..FFF***FFFF.FFF.FF.FF....FFFFFF..F...***FF*FF*FF**...***...FFFFFFFFFFFFFFF.FFFFFFFFFFFFFFFFFFFF.FFFFF...................FF....FF...............................*......*FFF......*......F..FF..F....FF.***FF....FF....FF.**FFFFFFF.F...*
8:57:50 AM ...Detected saf cli...generating STIG Viewer Checklist for 10.182.138.1
8:57:54 AM ...Disconnecting from vCenter

# Resulting output
> dir C:\inspec\Reports\Runner\

    Directory: C:\Inspec\Reports\Runner

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---           5/19/2023  8:51 AM         507413 VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.131.186-5-19-2023_8-48-29.ckl
-a---           5/19/2023  8:51 AM         580793 VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.131.186-5-19-2023_8-48-29.json
-a---           5/19/2023  8:54 AM         507403 VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.132.6-5-19-2023_8-48-29.ckl
-a---           5/19/2023  8:54 AM         580816 VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.132.6-5-19-2023_8-48-29.json
-a---           5/19/2023  8:57 AM         507403 VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.138.1-5-19-2023_8-48-29.ckl
-a---           5/19/2023  8:57 AM         580787 VMware_vSphere_7.0_STIG_ESXi_Inspec_Report_10.182.138.1-5-19-2023_8-48-29.json
```

## Auditing vCenter (Appliance Controls)
Auditing the vCenter appliance is done over SSH which must be enabled for the scan.

### Update the default shell for root
The default shell for root must be changed to `/bin/bash` before running. The appliance shell causes issues with some controls running.

```bash
# SSH to vCenter
Connected to service

    * List APIs: "help api list"
    * List Plugins: "help pi list"
    * Launch BASH: "shell"

Command> shell.set --enabled true
Command> shell
Shell access is granted to root
root@sc1-10-182-131-166 [ ~ ]# chsh -s /bin/bash root
```

### Run the audit
In this example we will be scanning the vCenter appliance, specifying an inputs file, and outputting a report to the CLI and to a JSON file.  

Updating the inputs file is not required for this profile but the `inputs-vcsa-7.0.yml` should be specified because it contains inputs for the Photon profile.  
```powershell
# Note this command is being ran from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec . -t ssh://root@10.182.131.166 --password 'password' --show-progress --input-file .\inputs-vcsa-7.0.yml --reporter=cli json:C:\InSpec\Reports\MyVCSAReport.json

# Shown below is the last part of the output at the CLI.
  [PASS]  VCUI-70-000028: vSphere UI must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the web server.
     [PASS]  Command: `rpm -V vsphere-ui|grep serviceability.xml|grep "^..5......"` stdout.strip is expected to eq ""
  [PASS]  VCUI-70-000029: vSphere UI log files must be moved to a permanent repository in accordance with site policy.
     [PASS]  Command: `rpm -V VMware-visl-integration|grep vmware-services-vsphere-ui.conf|grep "^..5......"` stdout.strip is expected to eq ""
  [PASS]  VCUI-70-000030: vSphere UI must be configured with the appropriate ports.
     [PASS]  5090 is expected to eq "5090"
     [PASS]  443 is expected to eq "443"
  [PASS]  VCUI-70-000031: vSphere UI must disable the shutdown port.
     [PASS]  XML /usr/lib/vmware-vsphere-ui/server/conf/server.xml ["/Server/@port"] is expected to cmp == "${shutdown.port}"
     [PASS]  JSON /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json StartCommandArgs is expected to include "-Dshutdown.port=-1"
  [PASS]  VCUI-70-000032: vSphere UI must set the secure flag for cookies.
     [PASS]  XML /usr/lib/vmware-vsphere-ui/server/conf/web.xml /web-app/session-config/cookie-config/secure is expected to cmp == "true"
  [PASS]  VCUI-70-000033: The vSphere UI default servlet must be set to "readonly".
     [PASS]  XML /usr/lib/vmware-vsphere-ui/server/conf/web.xml /web-app/servlet[servlet-name="default"]/init-param[param-name="readonly"]/param-value is expected to eq []


Profile Summary: 313 successful controls, 17 control failures, 0 controls skipped
Test Summary: 1516 successful, 106 failures, 0 skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

```powershell
# Converting the VCSA scan results from the prior section to CKL
saf convert hdf2ckl -i C:\inspec\Reports\MyVCSAReport.json -o C:\inspec\Reports\MyVCSAReport.ckl --hostname 10.182.131.166 --fqdn myvcenter.local --ip 10.182.131.166 --mac 00:00:00:00:00:00
```

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  

![alt text](/images/vsphere_audit7_ckl_screenshot.png)