---
title: "Audit VMware Aria Operations 8"
weight: 7
description: >
  Auditing VMware Aria Operations 8.x for STIG Compliance
---
## Overview
Auditing VMware Aria Operations for STIG compliance involves scanning the application, the web services, the vpostgres service, and the underlying Photon OS.  

When auditing VMware Aria Operations we will split up tasks between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration affecting availability of the product is low but could impact how the environment is operated if not assessed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc.) that make up the product. Altering these add risk to product availability if precautionary steps and care in implementation are not taken. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

The VMware Aria Operations auditing uses InSpec over an SSH connection. It is recommended to disable SSH after the auditing is complete.

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to utilize the versions listed here.  

* The [vmware-aria-operations-8x-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/aria/operations/8.x/v1r3-srg/inspec/vmware-aria-operations-8x-stig-inspec-baseline) profile downloaded.
* The [vmware-photon-4.0-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/photon/4.0/v1r5-srg/inspec/vmware-photon-4.0-stig-baseline) profile downloaded.
* InSpec/Cinc Auditor 6.6.0
* SAF CLI 1.4.0
* [STIG Viewer 2.17](https://public.cyber.mil/stigs/srg-stig-tools/)
* A VMware Aria Operations environment. Version 8.18 was used in these examples.
* An account with SSH access to VMware Aria Operations for Logs.

### Assumptions
* Commands are initiated from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository downloaded and extracted to `/usr/share/stigs`.
* CINC Auditor is used in lieu of InSpec. If InSpec is used replace `cinc-auditor` with `inspec` when running commands.

## Auditing VMware Aria Operations
### Update profile inputs
Included in each of the `vmware-aria-operations-8x-stig-baseline` sub-folders (application, apache, api, casa, ui, and vpostgres) is an inspec input file named 'inspec.yml'. 
Additionally, at the top level, an `inputs.yml` file can be created that "rolls up" all of the variables into one file, and can be utilized at the command line.

Evaluate each of the input files (`application/inspec.yml`, `apache\inspec.yml`, etc.), and if any of the input variables need to be over-ridden, then make sure those variables are included in the top level `inputs.yml` file. Examples are provided below.

#### VMware Aria Operations - Sample Inputs
```yaml
api-sessionTimeout:        "30"
api-maxThreads:            "300"
casa-sessionTimeout:       "30"
casa-maxThreads:           "300"
ui-sessionTimeout:         "30"
ui-maxThreads:             "300"
#vpostgres
tcpKeepAliveIdle:          "7200"
tcpKeepAliveInterval:      "75"
tcpKeepAliveCount:         "9"
```

### Update the SSH config to allow scan
If the VMware Aria Operations appliance has SSH access disabled, the scans will not be able to run. SSH must be temporarily enabled to complete the scan, then can be disabled again once the audit is complete.  

```bash
# Connect to the console through vCenter
vi /etc/ssh/sshd_config
# Update PermitRootLogin from no to yes and save
systemctl restart sshd
```

### Run the audit
In this example we will be scanning a target VMware Aria Operations appliance, specifying an inputs file, and outputting a report to the CLI and to a JSON file.  
```bash
# Note this command is run from the root of the profile folder. Update paths as needed (instead of '.', use './path/to/profile') if running from a different location.
> cinc-auditor exec . -t ssh://root@aria-ops.domain.path --password 'replaceme' --show-progress --input-file inputs.yml --reporter cli json:/tmp/reports/Aria_Ops_8x_STIG_Report.json

# Shown below is example output at the CLI.
  ✔  PHTN-50-000241: The Photon operating system must install rsyslog for offloading of audit logs.
     ✔  Service rsyslog is expected to be installed
  ✔  PHTN-50-000242: The Photon operating system must enable the rsyslog service.
     ✔  Service rsyslog is expected to be enabled
     ✔  Service rsyslog is expected to be running
  ✔  PHTN-50-000244: The Photon operating system must enable hardlink access control protection in the kernel.
     ✔  Kernel Parameter fs.protected_hardlinks value is expected to cmp == 1
  ✔  PHTN-50-000245: The Photon operating system must mount /tmp securely.
     ✔  ["mode=1777", "strictatime", "nosuid", "nodev", "size=50%%", "nr_inodes=1m", "noexec"] is expected to include "nosuid", "noexec", and "nodev"
  ✔  PHTN-50-000246: The Photon operating system must restrict core dumps.
     ✔  Kernel Parameter fs.suid_dumpable value is expected to eq 0 or eq 2

Profile Summary: zz successful controls, zz control failures, zz controls skipped
Test Summary: zz successful, zz failures, zz skipped
```

## Convert the results to CKL
If a STIG Viewer Checklist (CKL) file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

```bash
# Converting the scan results from the prior section to CKL
saf convert hdf2ckl -i /tmp/reports/Aria_Ops_8x_STIG_Report.json -o /tmp/reports/Aria_Ops_8x_STIG_Report.ckl --hostname aria-ops --fqdn aria-ops.domain.path --ip 10.10.10.20 --mac 00:00:00:00:00:00
```

Opening the CKL file in STIG Viewer will look like the example screenshot below. Note the InSpec results are included in the `Finding Details` pane.  
![STIG Viewer Checklist]({{< baseurl >}}/images/VROPS_ckl_screenshot.png)