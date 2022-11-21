# vmware-vsphere-esxi-7.0-stig-baseline
VMware vSphere ESXi 7.0 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 4 Date: 28 October 2022  
STIG Type: [STIG Readiness Guide](https://confluence.eng.vmware.com/pages/viewpage.action?pageId=1231779155)  
Maintainers: SCOPE/VMTA  

## How to run InSpec locally from Powershell on Windows

**Note - assumes profile is downloaded to C:\Inspec\Profiles\vmware-vsphere-esxi-7.0-stig-baseline**  
**Note - update inspec.yml with the appropriate environmental variables except the vmhostName**  
**Note - This profle must be run from Powershell or Powershell Core with the PowerCLI module installed**  

This profile uses the VMware train to execute PowerCLI commands.  As of the current release the best way to connect to a target vCenter is with environmental variables.

For Windows from PowerShell setup the following variables for the existing session
```
$env:VISERVER="vcenter.test.local"
$env:VISERVER_USERNAME="Administrator@vsphere.local"
$env:VISERVER_PASSWORD="password"
```

Run profile against a target ESXi host within vCenter and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-esxi-7.0-stig-baseline -t vmware:// --input vmhostName=IP or FQDN of target host as it appears in vCenter
```

Run profile against a target ESXi host within vCenter and show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-esxi-7.0-stig-baseline -t vmware:// --input vmhostName=IP or FQDN of target host as it appears in vCenter --show-progress --reporter=cli json:C:\Inspec\Reports\esxi.json
```

Run a single STIG Control against a target ESXi host within vCenter
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-esxi-7.0-stig-baseline -t vmware:// --input vmhostName=IP or FQDN of target host as it appears in vCenter --controls=ESXI-70-000001
```