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