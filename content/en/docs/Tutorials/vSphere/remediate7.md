---
title: "Remediate vSphere 7"
weight: 4
description: >
  Remediating vSphere 7 for STIG Compliance
---
## Overview
Remediating vSphere for STIG compliance involves configuring ESXi, Virtual Machines, vCenter, and the vCenter appliance.

When remediating vSphere we will split up tasks between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration affecting availability of the product is low but could impact how the environment is operated if not assessed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc) that make up the product. Altering these add risk to product availability without precautionary steps and care in implementation. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

To remediate vSphere, PowerCLI is the automation tool used, while for the VCSA we will use Ansible. For the vCenter appliance the remediation is performed via SSH. It is recommended to disable SSH on vCenter after configuration is complete.  

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vSphere 7.0 PowerCLI](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vsphere/powercli) scripts downloaded.
* The [vmware-vcsa-7.0-stig-ansible-hardening](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vcsa/ansible/vmware-vcsa-7.0-stig-ansible-hardening) playbook downloaded.
* PowerShell 7.3.4/PowerCLI 13.1
* [VMware.Vsphere.SsoAdmin PowerCLI Module 1.3.9](https://www.powershellgallery.com/packages/VMware.vSphere.SsoAdmin)
* A vSphere 7.x environment. 7.0 U3l was used in these examples.
* An account with sufficient privileges to configure vSphere.

### Create PowerShell credential for vCenter connection
The PowerCLI scripts provided use a [PowerShell Credential](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-credential) stored in a variable to authenticate to vCenter and should be established before attempting to run the scripts.  

```powershell
# Run the following command to generate a credential. Substitute the username as needed in the environment. Note if ran in PowerShell 5.x on Windows this will popup a window to enter the credentials.
$vccred = Get-Credential

PowerShell credential request
Enter the credentials.
User: administrator@vsphere.local
Password for user administrator@vsphere.local: ****************
```

## Remediating ESXi product controls
To remediate ESXi hosts a [PowerCLI script](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/powercli/VMware_vSphere_7.0_STIG_ESXi_Remediation.ps1) has been provided that will target a single host or a vSphere cluster based on parameters provided to the script.

**Note: There are some controls that cannot be remediated with PowerCLI and are not addressed by this script. The output will indicate that these are manual controls.**

### Gather environment information
In order to run the script effectively it must be provided the organization's environment specific information.  

Review the below parameters and gather the information needed to run the script:
```powershell
[CmdletBinding()]
param (
  [Parameter(Mandatory = $true)]
  [string]$vcenter,
  [Parameter(Mandatory = $true)]
  [pscredential]$vccred,
  [Parameter(Mandatory = $true, ParameterSetName = "hostname")]
  [string]$hostname,
  [Parameter(Mandatory = $true, ParameterSetName = "cluster")]
  [string]$cluster,
  [Parameter(Mandatory = $false,
    HelpMessage = "Enter the path for the output report. Example /tmp")]
  [string]$reportpath,    
  [Parameter(Mandatory = $true,
    HelpMessage = "Enter the Active Directory Admins group to use for administrative access to ESXi")]
  [string]$esxAdminGroup,
  [Parameter(Mandatory = $true,
    HelpMessage = "Enter allowed IP ranges for the ESXi firewall in comma separated format.  For Example `"192.168.0.0/16`",`"10.0.0.0/8`" ")]
  [string[]]$allowedIPs,
  [Parameter(Mandatory = $false,
    HelpMessage = "Enter the syslog server for the ESXi server(s). Example tcp://log.domain.local:514")]
  [string]$syslogServer,
  [Parameter(Mandatory = $false,
    HelpMessage = "Enable this option if VMware vRealize Log Insight is used to manage syslog on the ESXi host(s).")]
  [switch]$logInsight,
  [Parameter(Mandatory = $true,
    HelpMessage = "Enter NTP servers.  For Example `"10.1.1.1`",`"10.1.1.2`" ")]
  [string[]]$ntpServers,
  [Parameter(Mandatory = $false,
    HelpMessage = "Specify the native VLAN Id configured on the ports going to the ESXi Hosts.  If none is specified the default of 1 will be used.")]
  [string]$nativeVLAN = "1"
)
```

### Disabling Controls
The script includes variables to enable or disable controls by STIG ID. All controls are enabled by default and can be turned off by changing these variables to `$false` for a specific control.  

A snippet of these variables is shown below.  
```powershell
##### Enable or Disable specific STIG Remediations #####
$controlsenabled = [ordered]@{
  ESXI70000001 = $true  #Lockdown Mode
  ESXI70000002 = $true  #DCUI.Access List
  ESXI70000003 = $true  #Lockdown Mode Exceptions
  ESXI70000004 = $true  #Syslog
```

### Run remediation script on target ESXi hosts
This example will remediate all hosts in the vSphere cluster named `cluster0`. If running on a single host is desired, specify the `hostname` parameter instead of `cluster` and provide the hostname as displayed in vCenter.  
```powershell
# Running the script.
> .\VMware_vSphere_7.0_STIG_ESXi_Remediation.ps1 -vcenter 10.182.131.166 -vccred $vccred -cluster "cluster0" -esxAdminGroup "MyESXiGroup" -allowedIPs "10.0.0.0/8" -ntpServers "time-a-g.nist.gov","time-b-g.nist.gov" -syslogServer "tcp://loginsight.vmware.com:514" -reportpath C:\Temp

# Snippet from the output of running the script.
Transcript started, output file is C:\Temp\VMware_vSphere_7.0_STIG_ESXi_Remediation_Transcript_5-25-2023_9-26-8.txt
9:26:09 AM ...Core detected...checking for VMware.PowerCLI
9:26:09 AM ...Trying to import module VMware.PowerCLI
9:27:13 AM ...Connecting to vCenter 10.182.131.166
9:27:16 AM ...Gathering info on target hosts in 10.182.131.166
9:27:19 AM ...Found host 10.182.131.186
9:27:19 AM ...Found host 10.182.132.6
9:27:19 AM ...Found host 10.182.138.1
9:27:19 AM ...Remediating STIG ID:ESXI-70-000002 with Title: The ESXi host must verify the DCUI.Access list.
9:27:20 AM ...Setting DCUI.Access is already configured correctly to root on 10.182.131.186
9:27:20 AM ...Setting DCUI.Access is already configured correctly to root on 10.182.132.6
9:27:20 AM ...Setting DCUI.Access is already configured correctly to root on 10.182.138.1
9:27:20 AM ...Remediating STIG ID:ESXI-70-000003 with Title: The ESXi host must verify the exception users list for lockdown mode.
9:27:20 AM ...No exception users found on 10.182.131.186
9:27:20 AM ...No exception users found on 10.182.132.6
9:27:21 AM ...No exception users found on 10.182.138.1
9:27:21 AM ...Remediating STIG ID:ESXI-70-000004 with Title: Remote logging for ESXi hosts must be configured.
9:27:21 AM ...Setting Syslog.global.logHost was incorrectly set to  on 10.182.131.186...setting to tcp://loginsight.vmware.com:514

Name                 Value                Type                 Description
----                 -----                ----                 -----------
Syslog.global.logHo… tcp://loginsight.vm… VMHost
9:27:25 AM ...Setting Syslog.global.logHost was incorrectly set to  on 10.182.132.6...setting to tcp://loginsight.vmware.com:514
Syslog.global.logHo… tcp://loginsight.vm… VMHost
9:27:28 AM ...Setting Syslog.global.logHost was incorrectly set to  on 10.182.138.1...setting to tcp://loginsight.vmware.com:514
Syslog.global.logHo… tcp://loginsight.vm… VMHost

# A results file and PowerShell transcript is provided in the report path specified.
Directory: C:\Temp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---           5/25/2023  9:30 AM           6224 VMware_vSphere_7.0_STIG_ESXi_Remediation_Results_5-25-2023_9-26-8.json
-a---           5/25/2023  9:30 AM          89142 VMware_vSphere_7.0_STIG_ESXi_Remediation_Transcript_5-25-2023_9-26-8.txt
```

## Remediating virtual machines product controls
To remediate virtual machines a [PowerCLI script](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/powercli/VMware_vSphere_7.0_STIG_VM_Remediation.ps1) has been provided that will target a single VM, all VMs in a cluster, or all VMs in vCenter based on parameters provided to the script.  

**Note: There are some controls that cannot be remediated with PowerCLI and are not addressed by this script. See the scripts description text for more details.**

### Disabling Controls
For processing efficiency this script is not constructed to run each control individually, so the STIG ID variables to enable/disable controls are not included as in the ESXi/vCenter scripts. If it is desired to skip some controls they could be commented out in the `$vmconfig` variable in the script.  

### Run remediation script on target virtual machines
This example will remediate all hosts in the vSphere cluster named `cluster0`. If running on a single host is desired, specify the `hostname` parameter instead of `cluster` and provide the hostname as displayed in vCenter.  
```powershell
# Running the script.
> .\VMware_vSphere_7.0_STIG_VM_Remediation.ps1 -vcenter 10.182.131.166 -vccred $vccred -cluster "cluster0" -reportpath C:\Temp

# Snippet from the output of running the script.
Transcript started, output file is C:\Temp\VMware_vSphere_7.0_STIG_VM_Remediation_Transcript_5-25-2023_10-19-28.txt
10:19:28 AM ...Core detected...checking for VMware.PowerCLI
10:19:28 AM ...Connecting to vCenter Server 10.182.131.166
10:19:31 AM ...Getting PowerCLI objects for all virtual machines in cluster: cluster0
10:19:31 AM ...Remediating advanced settings on stig space test on 10.182.131.166
10:19:31 AM ...Setting isolation.device.connectable.disable does not exist on stig space test creating setting...

Name                 Value                Type                 Description
----                 -----                ----                 -----------
isolation.device.co… True                 VM
10:19:34 AM ...Setting isolation.tools.copy.disable does not exist on stig space test creating setting...
isolation.tools.cop… True                 VM
10:19:36 AM ...Setting isolation.tools.diskShrink.disable does not exist on stig space test creating setting...
isolation.tools.dis… True                 VM

# A results file and PowerShell transcript is provided in the report path specified.
Directory: C:\Temp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---           5/25/2023 10:20 AM           1055 VMware_vSphere_7.0_STIG_VM_Remediation_Results_5-25-2023_10-19-28.json
-a---           5/25/2023 10:22 AM          13150 VMware_vSphere_7.0_STIG_VM_Remediation_Transcript_5-25-2023_10-19-28.txt
```

## Remediating vCenter product controls
To remediate vCenter a [PowerCLI script](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/powercli/VMware_vSphere_7.0_STIG_vCenter_Remediation.ps1) has been provided that will target a single vCenter server.  

**Note: There are some controls that cannot be remediated with PowerCLI and are not addressed by this script. The output will indicate that these are manual controls.**

### Gather environment information
In order to run the script effectively it must be provided the organization's environment specific information.  

This script also uses the [VMware.Vsphere.SsoAdmin PowerCLI Module](https://www.powershellgallery.com/packages/VMware.vSphere.SsoAdmin) to configure vCenter SSO controls. This module connects to vCenter separately using the `Connect-SsoAdminServer` command that requires using an account that has sufficient privileges in vCenter to modify SSO settings.  

Review the below parameters and gather the information needed to run the script:
```powershell
[CmdletBinding()]
param (
  [Parameter(Mandatory=$true)]
  [string]$vcenter,
  [Parameter(Mandatory=$true)]
  [pscredential]$vccred,
  [Parameter(Mandatory=$false,
  HelpMessage="Enter the path for the output report. Example /tmp")]
  [string]$reportpath,
  [Parameter(Mandatory=$false,
  HelpMessage="If Netflow is used enter the collector IP address")]
  [string]$vcNetflowCollectorIp = "",
  [Parameter(Mandatory=$false,
  HelpMessage="To disable Netflow on all port groups if enabled set to true")]
  [boolean]$vcNetflowDisableonallPortGroups = $false
)
```

### Disabling Controls
The script includes variables to enable or disable controls by STIG ID. All controls are enabled by default and can be turned off by changing these variables to `$false` for a specific control.  

A snippet of these variables is shown below.  
```powershell
##### Enable or Disable specific STIG Remediations #####
$controlsenabled = [ordered]@{
  VCSA7000009 = $true  #TLS 1.2
  VCSA7000023 = $true  #SSO Login Attempts
  VCSA7000024 = $true  #SSO Banner - Manual
  VCSA7000034 = $true  #config.log.level
  VCSA7000057 = $true  #Plugins - Manual
```

### Run remediation script on target vCenter server
This example will remediate all controls on a target vCenter server.   
```powershell
# Running the script.
> .\VMware_vSphere_7.0_STIG_vCenter_Remediation.ps1 -vcenter 10.182.131.166 -vccred $vccred -reportpath C:\Temp

# Snippet from the output of running the script.
Transcript started, output file is C:\Temp\VMware_vSphere_7.0_STIG_ESXi_Remediation_Transcript_5-25-2023_11-30-58.txt
11:30:58 AM ...Core detected...checking for VMware.PowerCLI
11:30:58 AM ...Module VMware.PowerCLI is already imported.
11:30:58 AM ...Core detected...checking for VMware.Vsphere.SsoAdmin
11:30:58 AM ...Module VMware.Vsphere.SsoAdmin is already imported.
11:30:58 AM ...Connecting to vCenter Server 10.182.131.166
11:30:59 AM ...Connecting to vCenter SSO Server 10.182.131.166
11:31:00 AM ...Verifying vCenter 10.182.131.166 is version 7.0.x
11:31:00 AM ...vCenter 10.182.131.166 is version 7.0.3 continuing...
11:31:00 AM ...Getting PowerCLI objects for all virtual distributed switches in vCenter: 10.182.131.166
11:31:01 AM ...Getting PowerCLI objects for all virtual distributed port groups in vCenter: 10.182.131.166
11:31:02 AM ...Remediating STIG ID: VCSA-70-000009 with Title: The vCenter Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination using remote access.
11:31:02 AM ...!!This control must be remediated manually!!
11:31:02 AM ...Remediating STIG ID: VCSA-70-000023 with Title: The vCenter Server must enforce the limit of three consecutive invalid logon attempts by a user.
11:31:02 AM ...SSO login attempts set incorrectly on 10.182.131.166
11:31:03 AM ...Remediating STIG ID: VCSA-70-000024 with Title: The vCenter Server must display the Standard Mandatory DoD Notice and Consent Banner before logon.
11:31:03 AM ...!!This control must be remediated manually!!
11:31:03 AM ...Remediating STIG ID: VCSA-70-000034 with Title: The vCenter Server must produce audit records containing information to establish what type of events occurred.
11:31:03 AM ...Setting config.log.level is already configured correctly to info on 10.182.131.166

# A results file and PowerShell transcript is provided in the report path specified.
Directory: C:\Temp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---           5/25/2023 11:33 AM           2543 VMware_vSphere_7.0_STIG_vCenter_Remediation_Results_5-25-2023_11-33-25.json
-a---           5/25/2023 11:33 AM          18763 VMware_vSphere_7.0_STIG_vCenter_Remediation_Transcript_5-25-2023_11-33-25.txt
```

## Remediating vCenter server appliance controls
To remediate vCenter an [Ansible playbook](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vcsa/ansible/vmware-vcsa-7.0-stig-ansible-hardening) has been provided that will target a single vCenter server appliance over SSH and configure any non-compliant controls.  

Since Ansible can only be run from Linux based systems, the examples below are being run on an Ubuntu 22.04 WSL2 instance on Windows 11 for reference.  

### Backups
Before running it is highly advised to have a backup of the VCSA and/or snapshot available if a rollback is required. Also the playbook will back up files configured before performing updates and place them under the /tmp directory in a folder directly on the VCSA. 

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

### Ansible dependencies
The playbook is written to use the separate Photon 3.0 playbook available and must be installed as a role prior to running.  

Also there are two Ansible collections that must be installed if on a version of Ansible newer than 2.9.  

```bash
# Installing playbook requirements from the requirements.yml file provided.
ansible-galaxy role install -r requirements.yml
```

### Running the playbook
To run all of the VCSA controls, follow the example below.
```bash
# The -k parameter will prompt for password and we are using extra-vars to specify a variable file for the playbook to use.
> ansible-playbook -i 10.182.131.166, -u root playbook.yml -k -v --extra-vars @vars-vcenter-7.0U3eplus.yml

# Output example
SSH password:

PLAY [all] ********************************************************************************************************************************************************************************************************************

TASK [Gathering Facts] ********************************************************************************************************************************************************************************************************
ok: [10.182.131.166]

TASK [vmware-photon-3.0-stig-ansible-hardening : Include Photon] **************************************************************************************************************************************************************
included: /home/rlakey/.ansible/roles/vmware-photon-3.0-stig-ansible-hardening/tasks/photon.yml for 10.182.131.166

TASK [vmware-photon-3.0-stig-ansible-hardening : Create time stamp] ***********************************************************************************************************************************************************
ok: [10.182.131.166] => {"ansible_facts": {"backup_timestamp": "2023-05-25-12-25-58"}, "changed": false}

TASK [vmware-photon-3.0-stig-ansible-hardening : Backup files...if restoring be sure to restore permissions that original file had!!] *****************************************************************************************
ok: [10.182.131.166] => (item=/etc/rsyslog.conf) => {"ansible_loop_var": "item", "changed": false, "checksum": "7aa11dc58f144160e7e3dc2d40cb2f03a39a989c", "dest": "/tmp/ansible-backups-2023-05-25-12-25-58/rsyslog.conf", "gid": 0, "group": "root", "item": "/etc/rsyslog.conf", "md5sum": "d31d58ff2bbc5cff6b7f343c2580300c", "mode": "0644", "owner": "root", "size": 4000, "src": "/etc/rsyslog.conf", "state": "file", "uid": 0}
ok: [10.182.131.166] => (item=/etc/issue) => {"ansible_loop_var": "item", "changed": false, "checksum": "930cb25fc842aca6047cb9fc1bfbd6ea191e686f", "dest": "/tmp/ansible-backups-2023-05-25-12-25-58/issue", "gid": 0, "group": "root", "item": "/etc/issue", "md5sum": "f498b74a84aaa39e292d9b815899144d", "mode": "0644", "owner": "root", "size": 104, "src": "/etc/issue", "state": "file", "uid": 0}
ok: [10.182.131.166] => (item=/etc/audit/rules.d/audit.STIG.rules) => {"ansible_loop_var": "item", "changed": false, "checksum": "38f324fe67c6943e07ef1910b41dedeb0b256ca4", "dest": "/tmp/ansible-backups-2023-05-25-12-25-58/audit.STIG.rules", "gid": 0, "group": "root", "item": "/etc/audit/rules.d/audit.STIG.rules", "md5sum": "396d715044fc7a8d92a0332d3edb4112", "mode": "0640", "owner": "root", "size": 5080, "src": "/etc/audit/rules.d/audit.STIG.rules", "state": "file", "uid": 0}

TASK [vmware-photon-3.0-stig-ansible-hardening : PHTN-30-000001 - Update/Create audit.STIG.rules file] ************************************************************************************************************************
changed: [10.182.131.166] => {"changed": true, "checksum": "aaafa4e8c28743ce3cc22c818f28f4cb9a3f53b2", "dest": "/etc/audit/rules.d/audit.STIG.rules", "gid": 0, "group": "root", "md5sum": "91a31e7bbf9e3f0d7f390feb4360581b", "mode": "0640", "owner": "root", "size": 5180, "src": "/root/.ansible/tmp/ansible-tmp-1685039234.3606877-890-106251101523760/source", "state": "file", "uid": 0}
```

A more conservative and preferred approach is to target any non-compliant controls, or run each component separately, allowing for performing any functional testing in between.
```bash
# Providing the tag "eam" will instruct the playbook to only run the eam role. This tag can be seen in each roles task/main.yml file.
> ansible-playbook -i 10.182.131.166, -u root playbook.yml -k -v --extra-vars @vars-vcenter-7.0U3eplus.yml --tags eam

# Providing the tag "VCEM-70-000001" will instruct the playbook to only run task tagged with the STIG ID of VCEM-70-000001.
> ansible-playbook -i 10.182.131.166, -u root playbook.yml -k -v --extra-vars @vars-vcenter-7.0U3eplus.yml --tags VCEM-70-000001
```