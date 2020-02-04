# InSpec Profile
InSpec Profile for the vCenter 6.7 Appliance DISA STIG
---
Name: vCenter 6.7 Appliance DISA STIG  
Version: 6.7.0

## How to run Inspec locally from Powershell on Windows

**Assumes vcsa profile is downloaded to C:\Inspec\Profiles\vcsa**  

Run the entire profile against a target vCenter appliance

inspec exec C:\Inspec\Profiles\vcsa -t ssh://root@<vcsa IP or FQDN> --password '<password>'

Run the entire profile against a target vCenter appliance, report to the cli and json, and show progress

inspec exec C:\Inspec\Profiles\vcsa -t ssh://root@<vcsa IP or FQDN> --password '<password>' --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json

Run a specific VCSA STIG against a target vCenter appliance

inspec exec C:\Inspec\Profiles\vcsa -t ssh://root@<vcsa IP or FQDN> --password '<password>' --controls=/PHTN-10/

Run a single STIG Control against a target vCenter appliance

inspec exec C:\Inspec\Profiles\vcsa -t ssh://root@<vcsa IP or FQDN> --password '<password>' --controls=PHTN-10-000001

Specify the profile inputs at run time vs. editing the inspec.yaml

inspec exec C:\Inspec\Profiles\vcsa -t ssh://root@<vcsa IP or FQDN> --password '<password>' --input=photonIp=10.184.102.139 ntpServer=time.vmware.com syslogServer=test.local:514