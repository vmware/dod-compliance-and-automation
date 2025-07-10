---
title: "Audit VCF Operations 9.x"
weight: 1
description: >
  Auditing VCF Operations 9.x for STIG Compliance
---
## Overview
This tutorial covers auditing the Operations appliance in VCF deployments.  


The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.


### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* InSpec/Cinc Auditor 6.8.24
* SAF CLI 1.4.20
* STIG Viewer 2.17
* A VCF 9.0.0.0 or newer environment.
* SSH access to the Operations appliance.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* CINC Auditor is used in lieu of InSpec. If InSpec is used replace `cinc-auditor` with `inspec` when running commands.
* The `vmware-photon-5.0-stig-baseline` profile has been staged under the same parent folder as this `vmware-cloud-foundation-operations-stig-baseline` profile.

## Auditing Operations Appliance Rules
Auditing the Operations appliances is done over SSH which must be enabled for the scan.

### Run the audit
In this example an Operations cluster will be scanned, outputting a report to the CLI and to a JSON file.  

The below commands will vary depending on the deployment architecture. For clustered deployments each node should be audited individually.

Example deployment:
- Operations Master
- Operations Replica
- Operations Data
- Operations Cloud Proxy

{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Navigate to the InSpec profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-stig-baseline/

# Run the audit on the Operations Master Node
cinc-auditor exec . -t ssh://root@ops-master.rainpole.local --password 'password' --show-progress --enhanced-outcomes --reporter cli json:/tmp/reports/VCF_9_Operations_Master_Report.json

Profile Summary: 287 successful controls, 11 control failures, 0 controls not reviewed, 0 controls not applicable, 0 controls have error
Test Summary: 500 successful, 18 failures, 0 skipped

# Run the audit on the Operations Replica Node
cinc-auditor exec . -t ssh://root@ops-replica.rainpole.local --password 'password' --show-progress --enhanced-outcomes --reporter cli json:/tmp/reports/VCF_9_Operations_Replica_Report.json

Profile Summary: 287 successful controls, 11 control failures, 0 controls not reviewed, 0 controls not applicable, 0 controls have error
Test Summary: 500 successful, 18 failures, 0 skipped

# Run the audit on the Operations Data Node. Note only Photon and Apache HTTPD rules are applicable to the data nodes.
cinc-auditor exec . -t ssh://root@ops-data.rainpole.local --password 'password' --show-progress --enhanced-outcomes --controls /PHTN-50/ /VCFH-9X/ --reporter cli json:/tmp/reports/VCF_9_Operations_Data_Report.json

Profile Summary: 256 successful controls, 8 control failures, 0 controls not reviewed, 0 controls not applicable, 0 controls have error
Test Summary: 424 successful, 10 failures, 0 skipped

# Run the audit on the Operations Cloud Proxy. Note only Photon rules are applicable to cloud proxy nodes.
cinc-auditor exec . -t ssh://root@ops-cp.rainpole.local --password 'password' --show-progress --enhanced-outcomes --controls /PHTN-50/ --input-file inputs-vcf-operations-cp.yml --reporter cli json:/tmp/reports/VCF_9_Operations_Cloud_Proxy_Report.json

Profile Summary: 206 successful controls, 5 control failures, 0 controls not reviewed, 1 control not applicable, 0 controls have error
Test Summary: 278 successful, 25 failures, 1 skipped
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
vi /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-stig-baseline/saf_cli_hdf2ckl_metadata.json

"hostname": "ops.rainpole.local",
"hostip": "10.1.1.4",
"hostmac": "00:00:00:00:00:00",
"hostfqdn": "ops.rainpole.local",
{{< /tab >}}
{{< /tabpane >}}

### Run SAF CLI to create the CKL file
The following command will convert the json result from the InSpec audit into a STIG Checklist file and ensure the correct metadata is inserted so that it displays correctly in STIG Viewer.  
{{< tabpane text=false right=false persist=header >}}
{{% tab header="**Version**:" disabled=true /%}}
{{< tab header="9.0.0.0" lang="bash" >}}
# Convert the InSpec report to a STIG Checklist
saf convert hdf2ckl -i /tmp/reports/VCF_9_Operations_Master_Report.json -o /tmp/reports/VCF_9_Operations_Master_Report.ckl -m /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-stig-baseline/saf_cli_hdf2ckl_metadata.json
{{< /tab >}}
{{< /tabpane >}}

Repeat the previous steps for each node in the Operations deployment.  

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  
![STIG Viewer Checklist](../../../images/ops_audit9_ckl_screenshot.png)

## Next
If needed proceed to the remediation tutorial for the Operations appliance [here](/docs/tutorials/cloud-foundation-9.x/appliances/operations/remediate9-ops/).
