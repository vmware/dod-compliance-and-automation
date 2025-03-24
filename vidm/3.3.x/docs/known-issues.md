# Table of contents

- [VMware Identity Manager 3.3.x](#vmware-identity-manager-3.3.x)
  - [PHTN-30-000031 The grub2-mkpasswd-pbkdf2 command is not found](#phtn-30-000031-the-grub2-mkpasswd-pbkdf2-command-is-not-found)
  - [WOAT-3X-00000771 The server.xml file is read only](#woat-3X-000007/71-the-server.xml-file-is-read-only)
  - [WOAT-3X-000047 The check command generates a large list of files with incorrect permissions](#woat-3X-000047-the-check-command-generates-a-large-list-of-files-with-incorrect-permissions)
  - [WOAT-3X-000066 The fix text is unclear on how to address this control](#woat-3X-000066-the-fix-text-is-unclear-on-how-to-address-this-control)

# Known Issues

This document outlines known issues with the VMware Identity Manager 3.3.x STIG Readiness Guide content, including workarounds if known.

## What should I do if...

### I have additional questions about an issue listed here?

Each known issue links off to an existing GitHub issue. If you have additional questions or feedback, please comment on the issue.

### My issue is not listed here?

Please check the [open](https://github.com/vmware/dod-compliance-and-automation/issues) and [closed](https://github.com/vmware/dod-compliance-and-automation/issues?q=is%3Aissue+is%3Aclosed) issues in the issue tracker for the details of your bug. If you can't find it, or if you're not sure, open a new issue.

## VMware Identity Manager 3.3.x

### [PHTN-30-000031] The grub2-mkpasswd-pbkdf2 command is not found

Related issue: None

When running the `grub2-mkpasswd-pbkdf2` command in the fix text you see the below error:  

`-bash: grub2-mkpasswd-pbkdf2: command not found`  

**Workaround:**

- The vIDM appliance did not ship with the grub2 package installed which provides this command. Customers wishing to implement this control can install this package in two ways.

  1. If the vIDM appliance has internet access the package and be installed with the following command: `tdnf install grub2`
  2. If the vIDM appliance does not have internet access the `grub2` package can be downloaded from a system with access from the Photon package repo.
    * https://packages.vmware.com/photon/3.0/photon_updates_3.0_x86_64/x86_64/grub2-2.06-10.ph3.x86_64.rpm
    * Copy the package to the appliance and install with the rpm command, for example: `rpm -i <path to rpm>`
 
 ### [WOAT-3X-000007/71] The server.xml file is read only

Related issue: None

When editing the `/opt/vmware/horizon/workspace/conf/server.xml` file you are unable to save the file because it is readonly.    

**Workaround:**

- When saving the file in vi, add a ! to the write command to force the save, for example: `wq!`

 ### [WOAT-3X-000047] The check command generates a large list of files with incorrect permissions

Related issue: None

The check command output lists approximately 15,000 files indicating and issue with file permissions.      

**Workaround:**

- The default permissions in vIDM 3.3.7 are acceptable and is not a finding. If a future update to this guidance is done this check command will be updated to the following:
  * `find /opt/vmware/horizon/workspace/webapps/ -xdev -type f -a '(' -not -user root -o -not -group www ')' -exec ls -ld {} \;`

 ### [WOAT-3X-000066] The fix text is unclear on how to address this control

Related issue: None

In this control when auditing it, we are expecting a `setCharacterEncodingFilter` filter to exist only in the `/opt/vmware/horizon/workspace/conf/web.xml` file and not any of the other web.xml files listed.    

**Workaround:**

- In the `/opt/vmware/horizon/workspace/conf/web.xml` file the correct `filter` and `filter-mapping` nodes already exist and are just commented out. These can be found around lines 505 and 600.  
