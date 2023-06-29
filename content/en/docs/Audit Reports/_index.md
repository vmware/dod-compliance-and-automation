---
title: "Audit Reports"
linkTitle: "Audit Reports"
weight: 6
description: >
  Audit reports for the greenfield out of the box compliance posture are provided here for reference.
---
### Overview
Unless otherwise stated all reports are for new deployments and do not have any manual attestations applied.  

### Report Status Definitions
- **Passed**: Controls with an automated test that have passed or that have been checked manually and an [attestation](/docs/automation-tools/safcli/#creating-and-applying-manual-attestations) applied to the audit.  
- **Failed**: Controls with an automated test that have failed or that have been checked manually and an [attestation](/docs/automation-tools/safcli/#creating-and-applying-manual-attestations) applied to the audit.  
- **Not Applicable**: Controls that did not meet the conditions to audit. For example a requirement to configure secure LDAP is N/A if LDAP is not in use.  
- **Not Reviewed**: Controls that do not have an automated test and have been skipped.  