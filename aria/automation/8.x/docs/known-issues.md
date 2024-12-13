# Table of contents

- [vRA](#vra)
  - [VRAA-8X-000106 cpu limit setting varies by deployment size](#VRAA-8X-000106-cpu-limit-setting-varies-by-deployment-size)
- [Docker](#docker)
- [Photon](#photon)
- [Kubernetes](#kubernetes)

# Known Issues

This document outlines known issues with the vRA 8 STIG content, including workarounds if known.

## What should I do if...

### I have additional questions about an issue listed here?

Each known issue links off to an existing GitHub issue. If you have additional questions or feedback, please comment on the issue.

### My issue is not listed here?

Please check the [open](https://github.com/vmware/dod-compliance-and-automation/issues) and [closed](https://github.com/vmware/dod-compliance-and-automation/issues?q=is%3Aissue+is%3Aclosed) issues in the issue tracker for the details of your bug. If you can't find it, or if you're not sure, open a new issue.

## vRA
### [VRAA-8X-000106] CPU limit setting varies by deployment size.

Related issue: None

Depending on the size selected at deployment, the Aria Automation appliance may contain one of several different values for the cpuLimit option returned by the kubectl command. Current known values include "500m", "2000m", and "2". It is not recommended to change this value from its out of the box setting, and the intent of the control is to ensure the value has not been changed since deployment.

**Workaround:**

- The check output will be updated in a future release and the output with "500m", "2000m" or "2" as the value for the CPU limit can be considered compliant.

## Docker

## Photon

## Kubernetes
