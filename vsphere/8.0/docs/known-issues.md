# Table of contents

- [vCenter](#vcenter)
- [ESXi](#esxi)
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

### [ESXI-80-000239] When attempting to configure Allowed IPs for the ESXi firewall you may see an error for some services

Related issue: None

You may see the error `Invalid operation requested: Can not change allowed ip list this ruleset, it is owned by system service.` when configuring some services.  

Due to changes in the ESXi firewall some services are unable to be configured to restrict access via a list of IP addresses or ranges. See the [8.0 U2 release notes](https://docs.vmware.com/en/VMware-vSphere/8.0/rn/vsphere-vcenter-server-802-release-notes/index.html#Known%20Issues-Miscellaneous%20Issues) for more information.  

**Workaround:**

See the below output for a list of services that can be configured at this time.  

```
esxcli network firewall ruleset list

Name                         Enabled  Enable/Disable configurable  Allowed IP configurable
---------------------------  -------  ---------------------------  -----------------------
sshServer                       true                        false                     true
sshClient                      false                         true                     true
nfsClient                      false                        false                    false
nfs41Client                    false                        false                    false
dhcp                            true                        false                    false
dns                             true                         true                     true
snmp                           false                        false                     true
ntpClient                      false                        false                     true
CIMHttpServer                   true                        false                    false
CIMHttpsServer                 false                        false                     true
CIMSLP                         false                        false                     true
iSCSI                          false                        false                    false
vpxHeartbeats                   true                        false                    false
updateManager                   true                         true                     true
faultTolerance                  true                         true                     true
webAccess                       true                         true                     true
vMotion                         true                        false                    false
vSphereClient                   true                         true                     true
activeDirectoryAll             false                        false                    false
NFC                             true                        false                    false
HBR                             true                        false                    false
ftpClient                      false                         true                     true
httpClient                     false                         true                     true
gdbserver                      false                         true                     true
DVFilter                       false                         true                     true
DHCPv6                          true                        false                    false
DVSSync                         true                        false                    false
syslog                         false                         true                     true
WOL                             true                         true                     true
vSPC                           false                         true                     true
remoteSerialPort               false                         true                     true
rdt                             true                        false                    false
cmmds                           true                        false                    false
ipfam                          false                         true                     true
iofiltervp                      true                        false                    false
esxupdate                      false                        false                    false
vsanEncryption                 false                        false                    false
pvrdma                         false                         true                     true
vic-engine                     false                         true                     true
etcdClientComm                  true                        false                    false
etcdPeerComm                    true                        false                    false
settingsd                      false                        false                    false
vdfs                           false                        false                    false
gstored                        false                        false                    false
trusted-infrastructure-kmxd    false                        false                    false
iwarp-pm                       false                         true                     true
ptpd                           false                        false                     true
trusted-infrastructure-kmxa    false                        false                    false
nvmetcp                        false                        false                    false
esxio-orchestrator             false                        false                    false
esxioComm                      false                        false                     true
nvmemdns                       false                        false                    false
vltd                           false                        false                    false
vsanhealth-unicasttest         false                        false                    false
vsanmgmt-https-tunnel           true                        false                    false
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
