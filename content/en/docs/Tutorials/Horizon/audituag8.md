---
title: "Audit VMware Unified Access Gateway"
weight: 3
description: >
  Auditing VMware Unified Access Gateway for STIG Compliance
---
## Overview
Auditing Unified Access Gateway (UAG) STIG compliance involves scanning any UAG appliances for application settings as well as the underlying Photon OS settings.  

To audit the UAG using InSpec we utilize the ssh transport which connects to the target UAG and performs queries remotely. Additionally, REST API calls are initiated from the calling machine to the target UAG for certain controls.   

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* For UAG appliances: The [unified-access-gateway-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/horizon/8.0/inspec/unified-access-gateway-stig-baseline) profile downloaded.
* [InSpec/Cinc Auditor 5.22.3](/docs/automation-tools/inspec/)
* [SAF CLI 1.2.11](docs/automation-tools/safcli/)
* [STIG Viewer 2.17](https://public.cyber.mil/stigs/srg-stig-tools/)
* An account with sufficient privileges to connect to each machine.

## Auditing Horizon Connection Servers
### Update profile inputs
Included in the `unified-access-gateway-stig-baseline` is an example [inputs.yml](https://github.com/vmware/dod-compliance-and-automation/tree/master/horizon/8.0/inspec/unified-access-gateway-stig-baseline/inputs.yml) file with the following inputs relevant to the target Unified Access Gateway.

Update the inputs as shown below with values relevant to your environment.
```yaml
# Connection settings
fqdn: "uag.domain.name:9443"
user: "admin"
#password: ""

# Other parameters
connectionserver: 'hzn-cs.domain.name'
sessionTimeoutMilliseconds: 36000000
allowedCertAuth: ["CN=DOMAIN-CA, DC=DOMAIN, DC=NAME"]
warningBanner: "You are accessing a U.S. Government (USG) Information System (IS) ..."
maxConnectionsPerUser: 16
allowedCiphers: ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
adminUsers: ["admin"]
monitorUsers: ["restadmin"]
allowPCOIP: true
allowBLAST: true
allowTUNNEL: true
allowUDPTUNNEL: false
disableHTMLACCESS: false
secureRandomSource: /dev/urandom
clockSkewTolerance: 300
authoritativeNTPServers: ["time1.example.com","time2.example.com"]
enableTLS12: true
enableTLS13: false
```

### Run the audit
In this example we will be scanning a target Unified Access Gateway and outputting a report to the CLI and to a JSON file, run from a linux machine. The command should be run from within the InSpec profile directory. 

```bash
# Note this command is being run from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec . -t ssh://root@uag.domain.name --password 'replaceme' --show-progress --reporter cli json:/tmp/reports/UAG_STIG_Report.json

# Shown below is the last part of the output at the CLI.
Profile Summary: zz successful controls, zz control failures, zz controls skipped
Test Summary: zz successful, zz failures, zz skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

```powershell
# Converting the scan results from the prior section to CKL
saf convert hdf2ckl -i /tmp/reports/UAG_STIG_Report.json -o /tmp/reports/UAG_STIG_Report.ckl --hostname uag.domain.name --fqdn uag.domain.name --ip 10.2.3.4 --mac 00:00:00:00:00:00
```

Opening the CKL file in STIG Viewer will look similar to the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  

![alt text](/images/vcf_audit5_ckl_screenshot.png)