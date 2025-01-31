# Table of contents

- [API](#api)
- [Application](#application)
- [Apache](#apache)
- [Casa](#casa)
- [Postgres](#postgres)
  - [POSTGRES-PROFILE Controls only apply to primary node](#postgres-profile-postgres-controls-only-apply-to-primary-node)
- [UI](#ui)
- [Photon](#photon)
  - [PHTN-40-000073, PHTN-50-000073 Commands in check and fix do not produce expected results](#phtn-40-000073phtn-50-000073-commands-in-check-and-fix-do-not-produce-expected-results)
  - [PHTN-40-000133 Require users to reauthenticate for privilege escalation](#phtn-40-000133-require-users-to-reauthenticate-for-privilege-escalation)

# Known Issues

This document outlines known issues with the VMware Aria Operations 8 STIG content, including workarounds if known.

## What should I do if...

### I have additional questions about an issue listed here?

Each known issue links off to an existing GitHub issue. If you have additional questions or feedback, please comment on the issue.

### My issue is not listed here?

Please check the [open](https://github.com/vmware/dod-compliance-and-automation/issues) and [closed](https://github.com/vmware/dod-compliance-and-automation/issues?q=is%3Aissue+is%3Aclosed) issues in the issue tracker for the details of your bug. If you can't find it, or if you're not sure, open a new issue.

# Table of contents  

## API

## Application

## Apache

## Casa

## Postgres

### [POSTGRES-PROFILE] Postgres controls only apply to primary node

Related issue: none

In a clustered environment, the Postgres controls only need to be applied to the primary node running the replication service. On Data/Replica nodes, that service does not exist.

## UI

## Photon

### [PHTN-40-000073,PHTN-50-000073] Commands in check and fix do not produce expected results

Related issue: None

Running commands to check or fix permissions and file ownership on the '/var/log' directory always returns a value of 777, even after attempting to update the permissions.

**Workaround:**

- The '/var/log' entry is a symbolic link to the '/storage/log/var/log' directory, so the check needs to be performed on the underlying directory rather than on the symlink itself. This can be accomplished by any of the following methods:
  - Add a trailing slash ("/") to the directory in any commands 
    - stat -c "..." /var/log/
    - chmod 0755 /var/log/
  - Use the underlying folder instead
    - stat -c "..." /storage/log/var/log
    - chmod 0755 /storage/log/var/log
  
  
### [PHTN-40-000133] Require users to reauthenticate for privilege escalation

Related issue: None

The intent of this control is to ensure that accounts/permissions out of the box haven't been changed. The two accounts returned ("mpuser" and "admin") are both ok, as long as others are not returned. In future revisions of the STIG content for Operations (Photon 5 and later), this control has been removed.

**Workaround:**

- Utilize the waiver process to remove the control from the audit scope.
- If utilizing InSpec, include the "skip_control" directive:
  - In the file "aria/operations/8.x/v1r3-srg/inspec/vmware-aria-operations-8x-stig-inspec-baseline/controls/photon.rb"
  - Add a line for "skip_control 'PHTN-40-000133'", instructing InSpec to skip that control when performing the audit.