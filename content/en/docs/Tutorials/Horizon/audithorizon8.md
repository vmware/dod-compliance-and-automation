---
title: "Audit VMware Horizon 8"
weight: 3
description: >
  Auditing VMware Horizon 8 for STIG Compliance
---
## Overview
Auditing Horizon STIG compliance involves scanning any Horizon Connection Servers, Horizon Windows Agent machines, and Horizon Windows Client machines.  

To audit Horizon using InSpec we utilize the winrm transport which connects to the target Windows machine and performs queries remotely. Optionally, InSpec could be installed on the target machine directly and the queries could be performed locally.   

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* For Horizon Connection Servers: The [horizon-8-connection-server-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/horizon/8.0/inspec/horizon-8-connection-server-stig-baseline) profile downloaded.
* For Horizon Windows Agent machines: The [horizon-8-windows-agent-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/horizon/8.0/inspec/horizon-8-windows-agent-stig-baseline) profile downloaded.
* For Horizon Windows Client machines: The [horizon-8-windows-client-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/horizon/8.0/inspec/horizon-8-windows-client-stig-baseline) profile downloaded.
* [InSpec/Cinc Auditor 5.22.3](/docs/automation-tools/inspec/)
* [SAF CLI 1.2.11](docs/automation-tools/safcli/)
* [STIG Viewer 2.17](https://public.cyber.mil/stigs/srg-stig-tools/)
* An account with sufficient privileges to connect to each machine.

## Auditing Horizon Connection Servers
### Update profile inputs
Included in the `horizon-8-connection-server-stig-baseline` is an example [inputs.yml](https://github.com/vmware/dod-compliance-and-automation/tree/master/horizon/8.0/inspec/horizon-8-connection-server-stig-baseline/inputs.yml) file with the following inputs relevant to the target Horizon Connection Server.

Update the inputs as shown below with values relevant to your environment.
```yaml
# Connection settings
fqdn: "horizon-cs.domain.name"
domain: domain.name"
user: "administrator@domain.name"
#password: ""

# Other parameters
sslConfFolderPath: "C:\\Program Files\\VMware\\VMware View\\Server\\sslgateway\\conf"
blastGWFolderPath: "C:\\Program Files\\VMware\\VMware View\\Server\\appblastgateway"
vdmpath: "C:\\ProgramData\\VMware\\VDM\\logs"
expectedVersion: "8.6.0"
backupFrequency: "DAY_1"
vmware_vdm_perms: ["NT AUTHORITY\SYSTEM Allow  FullControl", "BUILTIN\Administrators Allow  FullControl", "NT AUTHORITY\NETWORK SERVICE Allow  FullControl"]
syslogAddresses: ["syslog1.domain.name:514", "syslog2.domain.name:514"]
allowedCertAuth: ["CN=DOMAIN-CA, DC=DOMAIN, DC=NAME"]
warningBanner: "You are accessing a U.S. Government (USG) Information System (IS) ..."
```

## Auditing Horizon Agent Machines
### Update profile inputs
Included in the `horizon-8-windows-agent-stig-baseline` is an example [inputs.yml](https://github.com/vmware/dod-compliance-and-automation/tree/master/horizon/8.0/inspec/horizon-8-windows-agent-stig-baseline/inputs.yml) file with the following inputs relevant to the target Horizon Agent Machine.

Update the inputs as shown below with values relevant to your environment.
```yaml
# Connection settings
fqdn: "horizon-agent.domain.name"
user: "administrator@domain.name"
#password: ""

# Other parameters
allowedConnectScripts: ["sample.bat"]
allowedDisconnectScripts: []
allowedReconnectScripts: []
```

## Auditing Horizon Client Machines
### Update profile inputs
Included in the `horizon-8-windows-client-stig-baseline` is an example [inputs.yml](https://github.com/vmware/dod-compliance-and-automation/tree/master/horizon/8.0/inspec/horizon-8-windows-client-stig-baseline/inputs.yml) file with the following inputs relevant to the target Horizon Client Machine.

Update the inputs as shown below with values relevant to your environment.
```yaml
# Connection settings
fqdn: "horizon-client.domain.name"
user: "administrator@domain.name"
#password: ""
```

## Run the audit
In this example we will be scanning a target Horizon Connection Server and outputting a report to the CLI and to a JSON file, run from a linux machine. The command should be run from within the InSpec profile directory. 
The same process can be performed from the Agent or Client directories.  

```bash
# Note this command is being run from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec . -t ssh://root@horizon-cs.domain.name --password 'replaceme' --show-progress --reporter cli json:/tmp/reports/Horizon_8_CS_STIG_Report.json

# Shown below is the last part of the output at the CLI.
Profile Summary: zz successful controls, zz control failures, zz controls skipped
Test Summary: zz successful, zz failures, zz skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

```powershell
# Converting the scan results from the prior section to CKL
saf convert hdf2ckl -i /tmp/reports/Horizon_8_CS_STIG_Report.json -o /tmp/reports/Horizon_8_CS_STIG_Report.ckl --hostname horizon-cs.domain.name --fqdn horizon-cs.domain.name --ip 10.2.3.4 --mac 00:00:00:00:00:00
```

Opening the CKL file in STIG Viewer will look similar to the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  

![alt text](/images/vcf_audit5_ckl_screenshot.png)