# Table of contents

- [vCenter](#vcenter)
- [ESXi](#esxi)
  - [ESXI-80-000232 Persistent audit storage and capacity should be configured before enabling audit logs](#esxi-80-000232-persistent-audit-storage-and-capacity-should-be-configured-before-enabling-audit-logs)
  - [ESXI-80-000239 When attempting to configure Allowed IPs for the ESXi firewall you may see an error for some services](#esxi-80-000239-when-attempting-to-configure-allowed-ips-for-the-esxi-firewall-you-may-see-an-error-for-some-services)
- [Virtual Machines](#vm)
- [VCSA](#vcsa)
  - [RESOLVED PHTN-30-000054/67 -S all is displayed in the check output](#phtn-30-000054/67--S-all-is-displayed-in-the-check-output)
  - [RESOLVED PHTN-30-000114 Multiple umask entries in check output](#phtn-30-000114-multiple-umask-entries-in-check-output)
  - [RESOLVED VCLU-80-000037 Path incorrect in check](vclu-80-000037-path-incorrect-in-check)

# Known Issues

This document outlines known issues with the vSphere 8 STIG content, including workarounds if known.

## What should I do if...

### I have additional questions about an issue listed here?

Each known issue links off to an existing GitHub issue. If you have additional questions or feedback, please comment on the issue.

### My issue is not listed here?

Please check the [open](https://github.com/vmware/dod-compliance-and-automation/issues) and [closed](https://github.com/vmware/dod-compliance-and-automation/issues?q=is%3Aissue+is%3Aclosed) issues in the issue tracker for the details of your bug. If you can't find it, or if you're not sure, open a new issue.

## vCenter

## ESXi

### [ESXI-80-000232] Persistent audit storage and capacity should be configured before enabling audit logs

Related issue: None

You may see log files under `/var/log` with a name similar to `vmsyslog.####.debug` with entries pertaining that your audit log location does not exist. This may lead to errors such as the var ramdisk being full, services failing to start, and other general issue with the ESXi host.

**Workaround:**

- The advanced settings `Syslog.global.auditRecord.storageCapacity` and `Syslog.global.logDir` should be configured and verified before enabling audit logs with the `Syslog.global.auditRecord.storageEnable` setting.
- If you have already done this and are experiencing issue follow the below steps:
  1. Make sure `Syslog.global.logDir` is configured and exists on persistent storage.
  2. Reboot the host
  3. Set `Syslog.global.auditRecord.storageEnable` to false
  4. Set `Syslog.global.auditRecord.storageEnable` to true

### [ESXI-80-000239] When attempting to configure Allowed IPs for the ESXi firewall you may see an error for some services

Related issue: None

You may see the error `Invalid operation requested: Can not change allowed ip list this ruleset, it is owned by system service.` when configuring some services.  

Due to changes in the ESXi firewall some services are unable to be configured to restrict access via a list of IP addresses or ranges. See the [8.0 U2 release notes](https://docs.vmware.com/en/VMware-vSphere/8.0/rn/vsphere-vcenter-server-802-release-notes/index.html#Known%20Issues-Miscellaneous%20Issues) for more information.  

**Workaround:**

As of 8.0 U2b most services are now once again user configurable for the Allowed IP settings. A future STIG update will clarify that services that are not user configurable are not in scope of the rule. See the below list for what is user configurable. 

```
esxcli network firewall ruleset list

Name                         Enabled  Enable/Disable configurable  Allowed IP configurable
---------------------------  -------  ---------------------------  -----------------------
sshServer                       true                         true                     true
sshClient                      false                         true                     true
nfsClient                      false                        false                    false
nfs41Client                    false                        false                    false
dhcp                            true                        false                     true
dns                             true                         true                     true
snmp                           false                        false                     true
ntpClient                      false                        false                     true
CIMHttpServer                   true                        false                     true
CIMHttpsServer                 false                        false                     true
CIMSLP                         false                        false                     true
iSCSI                          false                        false                     true
vpxHeartbeats                   true                        false                     true
updateManager                   true                         true                     true
faultTolerance                  true                         true                     true
webAccess                       true                         true                     true
vMotion                         true                        false                     true
vSphereClient                   true                         true                     true
activeDirectoryAll             false                        false                     true
NFC                             true                        false                     true
HBR                             true                        false                     true
ftpClient                      false                         true                     true
httpClient                     false                         true                     true
gdbserver                      false                         true                     true
DVFilter                       false                         true                     true
DHCPv6                          true                        false                     true
DVSSync                         true                        false                     true
syslog                         false                         true                     true
WOL                             true                         true                     true
vSPC                           false                         true                     true
remoteSerialPort               false                         true                     true
rdt                             true                        false                     true
cmmds                           true                        false                     true
ipfam                          false                         true                     true
iofiltervp                      true                        false                     true
esxupdate                      false                        false                     true
vsanEncryption                 false                        false                    false
pvrdma                         false                         true                     true
vic-engine                     false                         true                     true
etcdClientComm                  true                        false                     true
etcdPeerComm                    true                        false                     true
settingsd                      false                        false                     true
vdfs                           false                        false                     true
gstored                        false                        false                     true
trusted-infrastructure-kmxd    false                        false                    false
iwarp-pm                       false                         true                     true
ptpd                           false                        false                     true
trusted-infrastructure-kmxa    false                        false                    false
nvmetcp                        false                        false                     true
esxio-orchestrator             false                        false                     true
esxioComm                      false                        false                     true
nvmemdns                       false                        false                     true
proxy                          false                        false                    false
dpd                            false                        false                     true
vltd                           false                        false                     true
vsanhealth-unicasttest         false                        false                     true
vsanmgmt-https-tunnel           true                        false                     true
```

## VM

## VCSA

### [PHTN-30-000054/67] -S all is displayed in the check output

<mark style="background-color: #78BC20">**Resolved in STIG Version 1 Release 2**</mark>

Related issue: None

Since we are not specifying a specific syscall(all is implied) in the audit rules for these controls the "-S all" is displayed in the auditctl command output which is not included in the expected output in the check.  

**Workaround:**

- The check output will be updated in a future update and the output with "-S all" added can be considered compliant.

### [PHTN-30-000114] Multiple umask entries in check output

<mark style="background-color: #78BC20">**Resolved in STIG Version 1 Release 2**</mark>

Related issue: None

The check command output may show multiple umask entries such as UMASK 022 and UMASK 077.  

**Workaround:**

- Resolution included in product roadmap.  
- When multiple entries are present the last entry is enforced.  

### [VCLU-80-000037] Path incorrect in check

<mark style="background-color: #78BC20">**Resolved in STIG Version 1 Release 2**</mark>

Related issue: None

In the check command the path to the server.xml file is incorrectly referencing the eam service instead of lookupsvc.  

**Workaround:**

- The check command will be updated in a future STIG release as follows:  
```# xmllint --xpath "//Connector[(@port = '0') or not(@address)]" /usr/lib/vmware-lookupsvc/conf/server.xml```
