---
title: "Remediate vSphere 7"
weight: 2
description: >
  Remediating vSphere 7 for STIG Compliance
---
## Overview
Remediating vSphere for STIG compliance involves configuring ESXi, Virtual Machines, vCenter, and the vCenter appliance.

When remediating vSphere we will split up tasks between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration effecting availability of the product is low but could impact how the environment is operated if not assessed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc) that make up the product. Altering these add risk to product availability without precautionary steps and care in implementation. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

To remediate vSphere, PowerCLI is the automation tool used, while for the VCSA we will use Ansible. For the vCenter appliance the remediation is performed via SSH. It is recommended to disable SSH on vCenter after configuration is complete.  

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vSphere 7.0 PowerCLI](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vsphere/powercli) scripts downloaded.
* The [vmware-vcsa-7.0-stig-ansible-hardening](https://github.com/vmware/dod-compliance-and-automation/tree/master/vsphere/7.0/vcsa/ansible/vmware-vcsa-7.0-stig-ansible-hardening) playbook downloaded.
* Powershell 7.3.4/PowerCLI 13.1
* [VMware.Vsphere.SsoAdmin PowerCLI Module 1.3.9](https://www.powershellgallery.com/packages/VMware.vSphere.SsoAdmin)
* A vSphere 7.x environment. 7.0 U3l was used in these examples.
* An account with sufficient privileges to configure vSphere.

### Create Powershell credential for vCenter connection
The PowerCLI scripts provided use a [Powershell Credential](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-credential) stored in a varialbe to authenticate to vCenter and should be established before attempting to run the scripts.  

```powershell
# Run the following command to generate a credential. Substitute the username as needed in your environment. Note if ran in Powershell 5.x on Windows this will popup a window to enter the credentials.
$vccred = Get-Credential

PowerShell credential request
Enter your credentials.
User: administrator@vsphere.local
Password for user administrator@vsphere.local: ****************
```

## Remediating ESXi Hosts
To remediate ESXi hosts we have provided a [PowerCLI script](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/powercli/VMware_vSphere_7.0_STIG_ESXi_Remediation.ps1) that will target a single host or a vSphere cluster based on parameters provided to the script.

**Note: There are some controls that cannot be remediated with PowerCLI and are not addressed by this script. The output will indicate that these are manual controls.**

### Gather environment information
In order to run the script effectively it must be provided with the organizations environment specific information.  

Review the below parameters and gather the information eeded to run the script:
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
The script includes varialbes to enable or disable controls by STIG ID. All controls are all enabled by default and can be turned off by changing these variables to `$false` for a specific control.  

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

# A results file and Powershell transcript is provided in the report path specified.
Directory: C:\Temp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---           5/25/2023  9:30 AM           6224 VMware_vSphere_7.0_STIG_ESXi_Remediation_Results_5-25-2023_9-26-8.json
-a---           5/25/2023  9:30 AM          89142 VMware_vSphere_7.0_STIG_ESXi_Remediation_Transcript_5-25-2023_9-26-8.txt
```

## Remediating virtual machines
To remediate virtual machines we have provided a [PowerCLI script](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/7.0/vsphere/powercli/VMware_vSphere_7.0_STIG_VM_Remediation.ps1) that will target a single VM, all VMs in a cluster, or all VMs in vCenter based on parameters provided to the script.  

**Note: There are some controls that cannot be remediated with PowerCLI and are not addressed by this script. See the scripts description text for more details.**

### Disabling Controls
For processing efficiency it is not constructed to run each control individually so the STIG ID variables are not included to enabled/disable controls such as in the ESXi/vCenter scripts. If it is desired to skip some controls they could be commented out in the `$vmconfig` variable in the script.  

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

# A results file and Powershell transcript is provided in the report path specified.
Directory: C:\Temp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---           5/25/2023 10:20 AM           1055 VMware_vSphere_7.0_STIG_VM_Remediation_Results_5-25-2023_10-19-28.json
-a---           5/25/2023 10:22 AM          13150 VMware_vSphere_7.0_STIG_VM_Remediation_Transcript_5-25-2023_10-19-28.txt
```
