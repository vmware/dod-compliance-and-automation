# vmware-vsphere-vcenter-7.0-stig-baseline
Inspec Profile to validate the secure configuration of VMware vSphere vCenter version 7.0 against the draft DISA vSphere 7.0 STIG
Version: 7.0.0 Draft

## How to run InSpec locally from Powershell on Windows

**Note - assumes profile is downloaded to C:\Inspec\Profiles\vmware-vsphere-vcenter-7.0-stig-baseline**  
**Note - update inspec.yml with the appropriate environmental variables**  
**Note - This profle must be run from Powershell or Powershell Core with the PowerCLI module installed**  

This profile uses the VMware train to execute PowerCLI commands.  As of the current release the best way to connect to a target vCenter is with environmental variables.

For Windows from PowerShell setup the following variables for the existing session
```
$env:VISERVER="vcenter.test.local"
$env:VISERVER_USERNAME="Administrator@vsphere.local"
$env:VISERVER_PASSWORD="password"
```

Run profile against a target vCenter and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-vcenter-7.0-stig-baseline -t vmware://
```

Run profile against a target vCenter and show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-vcenter-7.0-stig-baseline -t vmware:// --show-progress --reporter=cli json:C:\Inspec\Reports\vcenter.json
```

Run a single STIG Control against a target ESXi host within vCenter
```
inspec exec C:\Inspec\Profiles\vmware-vsphere-vcenter-7.0-stig-baseline -t vmware:// --controls=VCSA-70-000001
```