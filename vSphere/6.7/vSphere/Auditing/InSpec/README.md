# InSpec Profile for VMware vSphere 6.7 Virtual Machines
Inspec Profile to audit vSphere 6.7 Virtual Machine DISA STIG Controls  
Name: vSphere 6.7  
Author: Ryan Lakey, Kasey Linden  
Status: Draft  
Copyright: VMware  
Copyright Email: rlakey@vmware.com  klinden@vmware.com  
Version: 6.7.0  

## Requirements
- Draft vSphere 6.7 Virtual Machine DISA STIG
- vSphere 6.7
- PowerCLI 11+
- Powershell 5+
- Tested with Inspec 4.16.0

## How to run

Run all controls on a single virtual machine and report to CLI
inspec exec .\vsphere-6.7\ -t vmware://<vcenter or esxi IP/FQDN> --user 'username' --password 'password' --reporter cli -input vmName=<Name of VM>

Run a single control on a single host and report to CLI
inspec exec .\vsphere-6.7\ -t vmware://<vcenter or esxi IP/FQDN> --user 'username' --password 'password' --reporter cli -input vmName=<Name of VM> --controls VMCH-67-000001

Run all controls on a single host and report to CLI and JSON for importing into Heimdall
inspec exec .\vsphere-6.7\ -t vmware://<vcenter or esxi IP/FQDN> --user 'username' --password 'password' --reporter cli json:/path/to/report.json -input vmName=<Name of VM>

## Misc

## License