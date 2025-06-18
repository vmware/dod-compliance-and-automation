---
title: "Audit VCF Operations for Networks 9.x"
weight: 1
description: >
  Auditing VCF Operations for Networks 9.x for STIG Compliance
---
## Overview
This tutorial covers auditing the Operations for Networks appliances in VCF deployments.  

{{% alert title="Important" color="primary" %}}
The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.
{{% /alert %}}

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* InSpec/Cinc Auditor 6.8.24
* SAF CLI 1.4.20
* STIG Viewer 2.17
* A VCF 9.0.0.0 or newer environment.
* SSH access to the Operations for Networks appliance.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* CINC Auditor is used in lieu of InSpec. If InSpec is used replace `cinc-auditor` with `inspec` when running commands.

## Auditing Operations for Networks Appliance Rules
Auditing the Operations for Networks appliance is done over SSH which must be enabled for the scan.

### Run the audit
In this example an Operations for Networks appliance will be scanned, outputting a report to the CLI and to a JSON file.  

If Operations for Networks is deployed as a cluster, repeat the following steps for each platform and proxy node.  

{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the InSpec profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-networks-stig-baseline/

# Run the audit on the platform node
cinc-auditor exec . -t ssh://support@opsnet1.rainpole.local --password 'password' --show-progress --enhanced-outcomes --sudo --reporter cli json:/tmp/reports/VCF_9_Operations_Net_Platform1_Report.json

Profile Summary: 275 successful controls, 101 control failures, 1 control not reviewed, 7 controls not applicable, 0 controls have error
Test Summary: 601 successful, 428 failures, 8 skipped

# Run the audit on the proxy node
cinc-auditor exec . -t ssh://support@opsnetproxy1.rainpole.local --password 'password' --show-progress --enhanced-outcomes --sudo --controls /UBTU/ --reporter cli json:/tmp/reports/VCF_9_Operations_Net_Proxy1_Report.json

Profile Summary: 229 successful controls, 85 control failures, 1 control not reviewed, 7 controls not applicable, 0 controls have error
Test Summary: 339 successful, 312 failures, 8 skipped
{{< /tab >}}
{{< /tabpane >}}
## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

### Update the target details in the metadata file
First update the target hostname, hostip, hostmac, and hostfqdn fields in the `saf_cli_hdf2ckl_metadata.json` metadata file
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Update the saf_cli_hdf2ckl_metadata.json file
vi /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-networks-stig-baseline/saf_cli_hdf2ckl_metadata.json

"hostname": "opsnet1.rainpole.local",
"hostip": "10.1.1.8",
"hostmac": "00:00:00:00:00:00",
"hostfqdn": "opsnet1.rainpole.local",
{{< /tab >}}
{{< /tabpane >}}

### Run SAF CLI to create the CKL file
The following command will convert the json result from the InSpec audit into a STIG Checklist file and ensure the correct metadata is inserted so that it displays correctly in STIG Viewer.  
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Convert the InSpec report to a STIG Checklist
saf convert hdf2ckl -i /tmp/reports/VCF_9_Operations_Net_Platform1_Report.json -o /tmp/reports/VCF_9_Operations_Net_Platform1_Report.ckl -m /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-networks-stig-baseline/saf_cli_hdf2ckl_metadata.json
{{< /tab >}}
{{< /tabpane >}}

Repeat for any additional nodes.  

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  
![STIG Viewer Checklist]({{< baseurl >}}images/opsnet_audit9_ckl_screenshot.png)

## Next
If needed proceed to the remediation tutorial for the Operations for Networks appliance [here](/docs/tutorials/cloud-foundation-9.x/appliances/operations-for-networks/remediate9-opsnet/).
