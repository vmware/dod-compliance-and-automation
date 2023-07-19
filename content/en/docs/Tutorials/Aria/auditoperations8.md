---
title: "Audit VMware Aria Operations 8"
weight: 3
description: >
  Auditing VMware Aria Operations 8 for STIG Compliance
---
## Overview
Auditing VMware Aria Operations for STIG compliance involves scanning the application, several Tomcat services within the application, the Postgres database, and the underlying Photon OS.

When auditing Aria Operations we will split up tasks between product and appliance based controls which are defined as follows:
* **Product Control:** Configurations that interact with the Product via the User Interface or API that are exposed to administrators. Whether these are Default or Non-Default, the risk of mis-configuration affecting availability of the product is low but could impact how the environment is operated if not assessed and addressed.
* **Appliance Control:** Appliance controls deal with the underlying components (databases, web servers, Photon OS, etc.) that make up the product. Altering these add risk to product availability without precautionary steps and care in implementation. Identifying and relying on Default settings in this category makes this category less risky (Default Appliance Controls should be seen as a positive).

To audit Aria Operations using InSpec we utilize the SSH transport. It is recommended to disable SSH on Aria Operations after the auditing is complete.  

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vmware-aria-operations-8.x-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/aria/8.x/operations/inspec/vmware-aria-operations-8.x-stig-baseline) InSpec profile downloaded.
* The [vmware-photon-3.0-stig-inspec-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/photon/3.0/inspec/vmware-photon-3.0-stig-inspec-baseline) profile downloaded.
* InSpec/Cinc Auditor 5.22.3
* SAF CLI 1.2.15
* STIG Viewer 2.17
* An Aria Operations 8.x environment. 8.12 was used in these examples.
* An account with access to Aria Operations.

## Auditing Aria Operations
### Update profile inputs
Included in the `vmware-aria-operationse-8.x-stig-baseline` is an example [inputs-example.yml](https://github.com/vmware/dod-compliance-and-automation/blob/master/vsphere/8.0/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/inputs-example.yml) file with the following inputs relevant to Aria Operations.

Update the inputs as shown below with values relevant to your environment. Specifically `syslogServer`,`sddcManager`,`bearerToken`,`sftpBackupsEnabled`,`sftpServer`,`ntpServers`,`currentVersion`,and `myVmwareAccount`.
```yaml
# Inputs for Photon OS.
authprivlog: /var/log/audit/auth.log
sshdcommand: "sshd -T -C 'user=vcf'"
# Enter environment specific syslog server with port. replace.local:514
syslogServer: 'replace.local:514'
# Inputs for PostgreSQL. No updates needed.
postgres_user: postgres
pg_data_dir: /data/pgdata/
pg_log_dir: /var/log/postgres
pg_owner: postgres
pg_group: users
# SDDC Manager Application
# Enter SDDC Manager FQDN/IP
sddcManager: 'sddc-manager.vsphere.local'
# Enter bearer token for API based tests
```

### Update the SSH config to allow scan
By default the Aria Operations appliance does not enable SSH logins so SSH must be temporarily enabled in order to complate the scan. These steps can be reversed once the audit is complete.  

```bash
# Allow root SSH into SDDC manager
ssh vcf@sddc-manager.vsphere.local
su -
vi /etc/ssh/sshd_config
# Update PermitRootLogin from no to yes and save
systemctl restart sshd
```

### Run the audit
In this example we will be scanning a target SDDC Manager, specifying an inputs file, and outputting a report to the CLI and to a JSON file ran from a linux machine.  
```bash
# Note this command is being ran from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec . -t ssh://root@sddc-manager.vsphere.local --password 'replaceme' --show-progress --input-file inputs-vcf-sddcmgr-5x-example.yml --reporter cli json:/tmp/reports/VCF_5.0.0_SDDC_Manager_STIG_Report.json

# Shown below is the last part of the output at the CLI.
  ✔  CFUI-5X-000019: The SDDC Manager UI service log files must only be accessible by privileged users.
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/access.log is expected not to be writable by others
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/access.log owner is expected to cmp == "vcf_sddc_manager_ui_app"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/access.log group is expected to cmp == "vcf"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/sddc-manager-ui-activity.log is expected not to be writable by others
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/sddc-manager-ui-activity.log owner is expected to cmp == "vcf_sddc_manager_ui_app"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/sddc-manager-ui-activity.log group is expected to cmp == "vcf"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/cspViolationReport.log is expected not to be writable by others
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/cspViolationReport.log owner is expected to cmp == "vcf_sddc_manager_ui_app"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/cspViolationReport.log group is expected to cmp == "vcf"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log is expected not to be writable by others
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log owner is expected to cmp == "vcf_sddc_manager_ui_app"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log group is expected to cmp == "vcf"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/supervisor.log is expected not to be writable by others
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/supervisor.log owner is expected to cmp == "vcf_sddc_manager_ui_app"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/supervisor.log group is expected to cmp == "vcf"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/user-logs/administrator-vsphere.local/administrator.server.log is expected not to be writable by others
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/user-logs/administrator-vsphere.local/administrator.server.log owner is expected to cmp == "vcf_sddc_manager_ui_app"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/user-logs/administrator-vsphere.local/administrator.server.log group is expected to cmp == "vcf"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/user-logs/administrator-vsphere.local/administrator.client.log is expected not to be writable by others
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/user-logs/administrator-vsphere.local/administrator.client.log owner is expected to cmp == "vcf_sddc_manager_ui_app"
     ✔  File /var/log/vmware/vcf/sddc-manager-ui-app/user-logs/administrator-vsphere.local/administrator.client.log group is expected to cmp == "vcf"
  ✔  CFUI-5X-000022: The SDDC Manager UI service must offload logs to a centralized logging server.
     ✔  File /etc/rsyslog.d/stig-services-sddc-manager-ui-app.conf content is expected to eq "module(load=\"imfile\" mode=\"inotify\")\ninput(type=\"imfile\"\n      File=\"/var/log/vmware/vcf/sd...     Tag=\"vcf-sddc-manager-ui-app-user-logs\"\n      Severity=\"info\"\n      Facility=\"local0\")"
  ✔  CFUI-5X-000034: The SDDC Manager UI service must have Web Distributed Authoring (WebDAV) disabled.
     ✔  Command: `(cd /opt/vmware/vcf/sddc-manager-ui-app/server/node_modules/ && npm list 2>/dev/null | grep webdav)` stdout.strip is expected to eq ""
  ✔  CFUI-5X-000044: The SDDC Manager UI service directory tree must be secured.
     ✔  Command: `find /opt/vmware/vcf/sddc-manager-ui-app/ -xdev -type f -a '(' -perm -o+w -o -not -user vcf_sddc_manager_ui_app -o -not -group vcf ')' -exec ls -ld {} \;` stdout.strip is expected to eq ""

Profile Summary: 200 successful controls, 9 control failures, 0 controls skipped
Test Summary: 974 successful, 21 failures, 0 skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

```powershell
# Converting the VCSA scan results from the prior section to CKL
saf convert hdf2ckl -i /tmp/reports/VCF_5.0.0_SDDC_Manager_STIG_Report.json -o /tmp/reports/VCF_5.0.0_SDDC_Manager_STIG_Report.ckl --hostname sddc-manager.vsphere.local --fqdn sddc-manager.vsphere.local --ip 10.2.3.4 --mac 00:00:00:00:00:00
```

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.
![alt text](/images/vcf_audit5_ckl_screenshot.png)