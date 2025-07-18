# Audit VCF Operations HCX 9.x
Auditing VCF Operations HCX 9.x for STIG Compliance

## Overview
This tutorial covers auditing the Operations HCX appliances in VCF deployments.  

The example commands below are specific to the product version and the supported STIG content for the version being run.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* InSpec/Cinc Auditor 6.8.24
* SAF CLI 1.4.20
* STIG Viewer 2.17
* A VCF 9.0.0.0 or newer environment.
* SSH access to the Operations HCX appliances.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* CINC Auditor is used in lieu of InSpec. If InSpec is used replace `cinc-auditor` with `inspec` when running commands.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* The `vmware-photon-5.0-stig-baseline` profile has been staged under the same parent folder as this `vmware-cloud-foundation-hcx-stig-baseline` profile.

## Auditing Operations HCX Appliance Rules
Auditing the Operations HCX appliances is done over SSH which must be enabled for the scan.

### Update the SSH config to allow scan
By default the Operations HCX appliance does not allow root SSH and the `admin` user does not have the required privileges to complete the scan so root SSH must be temporarily enabled to complete the scan. These steps can be reversed once the audit is complete.  

```bash
# Allow root SSH into Operations HCX
ssh admin@opshcxmgr.rainpole.local
su -
# Comment out the "AllowGroups secureall" line and restart sshd
sed -i 's/^[^#]*AllowGroups secureall/#&/' /etc/ssh/sshd_config
systemctl restart sshd
```

### Run the audit
In this example an Operations HCX appliance will be scanned, outputting a report to the CLI and to a JSON file.  

### Version: 9.0.0.0
```
# Navigate to the InSpec profile folder
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-hcx-stig-baseline/

# Run the audit on Operations HCX Manager appliances
cinc-auditor exec . -t ssh://root@opshcxmgr.rainpole.local --password 'password' --show-progress --enhanced-outcomes --reporter cli json:/tmp/reports/VCF_9_Operations_HCX_Mgr_Report.json

Profile Summary: 252 successful controls, 4 control failures, 0 controls not reviewed, 0 controls not applicable, 0 controls have error
Test Summary: 400 successful, 5 failures, 0 skipped

# Run the audit on Operations HCX Connector appliances (Photon 5 rules only)
cinc-auditor exec . -t ssh://root@opshcxconn1.rainpole.local --password 'password' --show-progress --enhanced-outcomes --controls=/PHTN-50/ --reporter cli json:/tmp/reports/VCF_9_Operations_HCX_Con1_Report.json

Profile Summary: 252 successful controls, 4 control failures, 0 controls not reviewed, 0 controls not applicable, 0 controls have error
Test Summary: 400 successful, 5 failures, 0 skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

### Update the target details in the metadata file
First update the target hostname, hostip, hostmac, and hostfqdn fields in the `saf_cli_hdf2ckl_metadata.json` metadata file
### Version: 9.0.0.0
```
# Update the saf_cli_hdf2ckl_metadata.json file
vi /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-hcx-stig-baseline/saf_cli_hdf2ckl_metadata.json

"hostname": "opshcxmgr.rainpole.local",
"hostip": "10.1.1.10",
"hostmac": "00:00:00:00:00:00",
"hostfqdn": "opshcxmgr.rainpole.local",
```

### Run SAF CLI to create the CKL file
The following command will convert the json result from the InSpec audit into a STIG Checklist file and ensure the correct metadata is inserted so that it displays correctly in STIG Viewer.  
### Version: 9.0.0.0
```
# Convert the InSpec report to a STIG Checklist
saf convert hdf2ckl -i /tmp/reports/VCF_9_Operations_HCX_Mgr_Report.json -o /tmp/reports/VCF_9_Operations_HCX_Mgr_Report.ckl -m /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-operations-hcx-stig-baseline/saf_cli_hdf2ckl_metadata.json
```

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  
![STIG Viewer Checklist](../../../../../images/opshcx_audit9_ckl_screenshot.png)

## Next
If needed proceed to the remediation tutorial for the Operations HCX appliances [here](./remediate9-opshcx.md).
