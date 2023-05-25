# Table of contents

- [vCenter](#vcenter)
- [ESXi](#esxi)
- [Virtual Machines](#vm)
- [VCSA](#vcsa)
  - [PHTN-30-000054/67 -S all is displayed in the check output](#phtn-30-000054/67--S-all-is-displayed-in-the-check-output)
  - [PHTN-30-000114 Multiple umask entries in check output](#phtn-30-000114-multiple-umask-entries-in-check-output)
  - [VCLU-80-000037 Path incorrect in check](vclu-80-000037-path-incorrect-in-check)

# Known Issues

This document outlines known issues with the vSphere 8 STIG content, including workarounds if known.

## What should I do if...

### I have additional questions about an issue listed here?

Each known issue links off to an existing GitHub issue. If you have additional questions or feedback, please comment on the issue.

### My issue is not listed here?

Please check the [open](https://github.com/vmware/dod-compliance-and-automation/issues) and [closed](https://github.com/vmware/dod-compliance-and-automation/issues?q=is%3Aissue+is%3Aclosed) issues in the issue tracker for the details of your bug. If you can't find it, or if you're not sure, open a new issue.

## vCenter

## ESXi

## VM

## VCSA

### [PHTN-30-000054/67] -S all is displayed in the check output

Related issue: None

Since we are not specifying a specific syscall(all is implied) in the audit rules for these controls the "-S all" is displayed in the auditctl command output which is not included in the expected output in the check.  

**Workaround:**

- The check output will be updated in a future update and the output with "-S all" added can be considered compliant.

### [PHTN-30-000114] Multiple umask entries in check output

Related issue: None

The check command output may show multiple umask entries such as UMASK 022 and UMASK 077.  

**Workaround:**

- Resolution included in product roadmap.  
- When multiple entries are present the last entry is enforced.  

### [VCLU-80-000037] Path incorrect in check

Related issue: None

In the check command the path to the server.xml file is incorrectly referencing the eam service instead of lookupsvc.  

**Workaround:**

- The check command will be updated in a future STIG release as follows:  
```# xmllint --xpath "//Connector[(@port = '0') or not(@address)]" /usr/lib/vmware-lookupsvc/conf/server.xml```
