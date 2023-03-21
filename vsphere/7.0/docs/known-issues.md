# Table of contents

- [vCenter](#vcenter)
  - [VCSA-70-000077 FIPS mode and Smart Card authentication compatibility](#vcsa-70-000077-fips-mode-and-smart-card-authentication-compatibility)
  - [VCSA-70-000285 Other default roles have cryptographic permissions](#vcsa-70-000285-other-default-roles-have-cryptographic-permissions)
- [ESXi](#esxi)
  - [ESXI-70-000084 Incorrect property shown in check](#esxi-70-000084-incorrect-property-shown-in-check)
- [Virtual Machines](#vm)
- [VCSA](#vcsa)
  - [VCEM-70-000008 The check command displays files that have changed](#vcem-70-000008-the-check-command-displays-files-that-have-changed)
  - [VCLU-70-000007 Log file permissions do not persist](#vclu-70-000007-log-file-permissions-do-not-persist)
  - [VCPG-70-000006 The check command output may display some tables not owned by vc](#vcpg-70-000006-the-check-command-output-may-display-some-tables-not-owned-by-vc)
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

## VM

**No issues reported at this time**

## VCSA

### [VCEM-70-000008] The check command displays files that have changed

Related issue: [#100](https://github.com/vmware/dod-compliance-and-automation/issues/100)

This issue is seen after some upgrades where some files may be replaced or configuration changed. Most commonly the "/etc/vmware-eam/version" is shown in the output which is updated on upgrades.

**Workaround:**

- Run the following command to exclude files marked as configuration files for the service.  
```rpm -V vmware-eam|grep "^..5......" | grep -v 'c /' | grep -v -E ".installer|.properties|.xml"```

### [VCLU-70-000007] Log file permissions do not persist

Related issue: [#133](https://github.com/vmware/dod-compliance-and-automation/issues/133)

In vCenter versions 7.0 U3f and above the Lookup service logs are no longer owned by root and now owned by the "lookupsvc" service account.

**Workaround:**

- The check command will be updated in a future STIG release as follows:
```find /var/log/vmware/lookupsvc -xdev -type f -a '(' -perm /137 -o -not -user lookupsvc -o -not -group lookupsvc ')' -exec ls -ld {} \;```

### [VCPG-70-000006] The check command output may display some tables not owned by vc

Related issue: [#139](https://github.com/vmware/dod-compliance-and-automation/issues/139)

This issue is seen after some upgrades where updates are made to the vCenter database.

**Workaround:**

- The tables can be left as is with the "postgres" owner or the owner can be updated to the "vc" user with the command in the fix text.  

### [VCST-70-000028] New port for smartcard authentication in 7.0 U3i

Related issue: [#135](https://github.com/vmware/dod-compliance-and-automation/issues/135)

As of vCenter 7.0 U3i the port for smartcard authentication has been updated to 3128. [See documentation](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.authentication.doc/GUID-DE48ED27-E48B-4FDA-B3C8-DD7127BF6879.html)]

**Workaround:**

- The check output will now list an additional port `bio-ssl-clientauth.https.port=3128` and should not be removed.
