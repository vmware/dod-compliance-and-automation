---
title: "Audit vSphere 7"
weight: 1
description: >
  Auditing vSphere 7 for STIG Compliance
---
## Overview
Auditing vSphere for STIG compliance involves scanning ESXi, Virtual Machines, vCenter, and the vCenter appliance.

When auditing vSphere we will also split auditing up between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration effecting availability of the product is low but could impact how the environment is operated if not assessed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc) that make up the product. Altering these add risk to product availability without precautionary steps and care in implementation. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

To audit vSphere using InSpec we utilize the VMware transport(train-vmware) which connects to vCenter via PowerCLI and performs queries. For the vCenter appliance the auditing is performed via SSH. It is recommended to disable SSH on vCenter after the auditing is complete.  

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* Powershell 7.3.4/PowerCLI 13.1
* [VMware.Vsphere.SsoAdmin PowerCLI Module 1.3.9](https://www.powershellgallery.com/packages/VMware.vSphere.SsoAdmin)
* InSpec/Cinc Auditor 5.22.3
* train-vmware 0.2.0
* The [vmware-vsphere-7.0-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vsphere/inspec/vmware-vsphere-7.0-stig-baseline) profile downloaded.
* The [vmware-vcsa-7.0-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vcsa/inspec/vmware-vcsa-7.0-stig-baseline) profile downloaded.
* A vSphere 7.x environment. 7.0 U3l was used in these examples.
* An account with sufficient privileges to view SSO configuration in vCenter.

### Install the custom VMware transport for InSpec
To extend the functionality of the VMware transport that ships with InSpec we have created a custom one that also incorporates the `VMware.Vsphere.SsoAdmin` module to extend automation coverage to the vCenter SSO STIG controls.  

To install the plugin that is included with the `vmware-vsphere-7.0-stig-baseline` profile, do the following:
```powershell
# Install the custom train-vmware plugin. Update the path to the gem as needed. The command will be the same on Windows and Linux.
> inspec plugin install C:\gitlab\vmware-vsphere-7.0-stig-baseline\train-vmware-0.2.0.gem

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
> inspec exec . -t vmware:// --show-progress --input-file .\inputs-example.yml --enhanced-outcomes --reporter=cli json:C:\InSpec\Reports\MyvSphereReport.json
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
