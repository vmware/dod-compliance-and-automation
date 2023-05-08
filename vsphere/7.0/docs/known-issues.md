# Table of contents

- [vCenter](#vcenter)
  - [VCSA-70-000077 FIPS mode and Smart Card authentication compatibility](#vcsa-70-000077-fips-mode-and-smart-card-authentication-compatibility)
  - [VCSA-70-000285 Other default roles have cryptographic permissions](#vcsa-70-000285-other-default-roles-have-cryptographic-permissions)
- [ESXi](#esxi)
  - [ESXI-70-000084 Incorrect property shown in check](#esxi-70-000084-incorrect-property-shown-in-check)
  - [ESXI-70-000084 Audit storage capacity reverts on reboot](#esxi-70-000084-audit-storage-capacity-reverts-on-reboot)
- [Virtual Machines](#vm)
  - [VMCH-70-000023 The 3D setting may not be displayed in the UI](#vmch-70-000023-the-3d-setting-may-not-be-displayed-in-the-ui)
  - [VMCH-70-000024 Check command does not display the expected output](#vmch-70-000024-check-command-does-not-display-the-expected-output)
- [VCSA](#vcsa)
  - [PHTN-30-000054/67 -S all is displayed in the check output](#phtn-30-000054/67--S-all-is-displayed-in-the-check-output)
  - [PHTN-30-000114 Multiple umask entries in check output](#phtn-30-000114-multiple-umask-entries-in-check-output)
  - [VCEM-70-000008 The check command displays files that have changed](#vcem-70-000008-the-check-command-displays-files-that-have-changed)
  - [VCLU-70-000007 Log file permissions do not persist](#vclu-70-000007-log-file-permissions-do-not-persist)
  - [VCPG-70-000006 The check command output may display some tables not owned by vc](#vcpg-70-000006-the-check-command-output-may-display-some-tables-not-owned-by-vc)
  - [VCPG-70-000020 The UTC timezone may be displayed in different formats](#vcpg-70-000020-the-utc-timezone-may-be-displayed-in-different-formats)
  - [VCST-70-000006 Max days line in output](#vcst-70-000006-max-days-line-in-output)
  - [VCST-70-000021 async-supported location](#vcst-70-000021-async-supported-location)
  - [VCST-70-000028 New port for smartcard authentication in 7.0 U3i](#vcst-70-000028-new-port-for-smartcard-authentication-in-70-u3i)

# Known Issues

This document outlines known issues with the vSphere 7 STIG content, including workarounds if known.

## What should I do if...

### I have additional questions about an issue listed here?

Each known issue links off to an existing GitHub issue. If you have additional questions or feedback, please comment on the issue.

### My issue is not listed here?

Please check the [open](https://github.com/vmware/dod-compliance-and-automation/issues) and [closed](https://github.com/vmware/dod-compliance-and-automation/issues?q=is%3Aissue+is%3Aclosed) issues in the issue tracker for the details of your bug. If you can't find it, or if you're not sure, open a new issue.

## vCenter

### [VCSA-70-000077] FIPS mode and Smart Card authentication compatibility

Related issue: None

In 7.0 U2 a global FIPS mode feature was made available for the vCenter appliance. Enabling this came with the caveat that Smart Card authentication is not supported with FIPS mode.

**Workaround:**

- OCSP recovation validation will no longer function and should be disabled. CRL recovation validation can be utilized instead to provide certificate revocation validation.

### [VCSA-70-000285] Other default roles have cryptographic permissions

Related issue: [#137](https://github.com/vmware/dod-compliance-and-automation/issues/137)

In the check and fix only the Administrator role is listed as having cryptographic permissions by default.

**Workaround:**

- The "No Trusted Infrastructure Administrator", "vCLSAdmin", and "vSphere Kubernetes Manager" roles also have some cryptographic related permissions out of the box and cannot be modified.
- Monitor users and groups assigned to these roles as you would any other group. There may be some system level accounts with these roles by default.

## ESXi

### [ESXI-70-000084] Incorrect property shown in check

Related issue: [#122](https://github.com/vmware/dod-compliance-and-automation/issues/122)

In the check exmaple output "Audit Remote Host Enabled" should read "Audit Record Remote Transmission Active". The fix steps are correct as is.

**Workaround:**

- None. Check text will be updated in a future release.
- The InSpec test has been updated to reflect the correct value.

### [ESXI-70-000084] Audit storage capacity reverts on reboot

Related issue: None

If audit storage capacity is configured to something other than 4, for example 100, after a reboot when querying the configuration it is reported as 4.

**Workaround:**

- The configuration is actually updated but the command is not reflecting the correct value. This can be confirmed by viewing the audit log folder and the number of files present.
- Each audit log is 1Mb so if 100 is configured you will see 100 files in the folder.
- Note you may see more than 100 files due to another bug but only 100 will be used.

## VM

### [VMCH-70-000023] The 3D setting may not be displayed in the UI

Related issue: None

By default the "mks.enable3d" parameter is not displayed in the vSphere UI when viewing the advanced settings list for a VM. If enabled or explicitly set to False it will then show up in the list.  
The ESXI Host Client also doesn't display this setting in either case even if explicitly specified.  

**Workaround:**

- If the setting does not exist in the vSphere UI and/or PowerCLI it is equivalent to being set to False.  
- The "Enable 3D Support" checkbox on a virtual machines video card can also be used to determine the status of this setting.    

### [VMCH-70-000024] Check command does not display the expected output

Related issue: [#146](https://github.com/vmware/dod-compliance-and-automation/issues/146)

The check command logic is incorrectly using "or" instead of "and".

**Workaround:**

- Run the following command instead:  
```Get-VM | Where {($_.ExtensionData.Config.MigrateEncryption -eq "disabled")}```  

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

### [VCEM-70-000008] The check command displays files that have changed

Related issue: [#100](https://github.com/vmware/dod-compliance-and-automation/issues/100)

This issue is seen after some upgrades where some files may be replaced or configuration changed. Most commonly the "/etc/vmware-eam/version" is shown in the output which is updated on upgrades.

**Workaround:**

- Run the following command to exclude files marked as configuration files for the service.  
```rpm -V vmware-eam|grep "^..5......" | grep -v 'c /' | grep -v -E ".installer|.properties|.xml"```

### [VCLU-70-000007] Log file permissions do not persist

Related issue: [#133](https://github.com/vmware/dod-compliance-and-automation/issues/133)

In vCenter versions 7.0 U3f and above the Lookup service logs are no longer owned by root and now owned by the "lookupsvc" service account. This is expected and the STIG will be updated for this change.

**Workaround:**

- The check command will be updated in a future STIG release as follows:  
```find /var/log/vmware/lookupsvc -xdev -type f -a '(' -perm /137 -o -not -user lookupsvc -o -not -group lookupsvc ')' -exec ls -ld {} \;```

### [VCPG-70-000006] The check command output may display some tables not owned by vc

Related issue: [#139](https://github.com/vmware/dod-compliance-and-automation/issues/139)

This issue is seen after some upgrades where updates are made to the vCenter database.

**Workaround:**

- The tables can be left as is with the "postgres" owner or the owner can be updated to the "vc" user with the command in the fix text.  
- The command in the fixtext should read as follows:  
```/opt/vmware/vpostgres/current/bin/psql -d VCDB -U postgres -c "ALTER TABLE <tablename> OWNER TO vc;"```

### [VCPG-70-000020] The UTC timezone may be displayed in different formats

Related issue: [#165](https://github.com/vmware/dod-compliance-and-automation/issues/165)

The UTC timezone has multiple names in PostgreSQL and may be configured with any of them.  

**Workaround:**

- All of the timezone names below correlate to the UTC timezone abbreviation and are not a finding if configured.
```
     name      | abbrev | utc_offset | is_dst
---------------+--------+------------+--------
 Universal     | UTC    | 00:00:00   | f
 UCT           | UTC    | 00:00:00   | f
 Zulu          | UTC    | 00:00:00   | f
 UTC           | UTC    | 00:00:00   | f
 Etc/Universal | UTC    | 00:00:00   | f
 Etc/UCT       | UTC    | 00:00:00   | f
 Etc/Zulu      | UTC    | 00:00:00   | f
 Etc/UTC       | UTC    | 00:00:00   | f
```

### [VCST-70-000006] Max days line in output

Related issue: None

In the command output you may see an additional line "1catalina.org.apache.juli.FileHandler.maxDays = 10"  

**Workaround:**

- This line will be added to a future STIG update and should not be removed.

### [VCST-70-000021] async-supported location

Related issue: [#166](https://github.com/vmware/dod-compliance-and-automation/issues/166)

The location of the `<async-supported>true</async-supported>` line differs in the ansible playbook and the check text.  
This line is also not directly related to the filter being implemented and its purpose, but how the filter processes requests. See [Set_Character_Encoding_Filter](https://tomcat.apache.org/tomcat-10.0-doc/config/filter.html#Set_Character_Encoding_Filter)  

**Workaround:**

- The `<async-supported>true</async-supported>` will work in any location as long as it is properly indented and is not intended to be a finding based on this.
- The location the ansible playbook places the line is in relation to the XML Schema and where it will pass validation should XML schema validation be enabled.

### [VCST-70-000028] New port for smartcard authentication in 7.0 U3i

Related issue: [#135](https://github.com/vmware/dod-compliance-and-automation/issues/135)

As of vCenter 7.0 U3i the port for smartcard authentication has been updated to 3128. [See documentation](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.authentication.doc/GUID-DE48ED27-E48B-4FDA-B3C8-DD7127BF6879.html)  

See also KB article: https://kb.vmware.com/s/article/90542  

**Workaround:**

- The check output will now list an additional port `bio-ssl-clientauth.https.port=3128` and should not be removed.
