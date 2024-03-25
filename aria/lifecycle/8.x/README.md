# VMware Aria Suite Lifecycle 8.x STIG Compliance and Automation

## Compatibility
The table below provides supported interoperability between product and STIG versioning. Application of STIG content outside interoperable versions is not supported.

|                     |        V1R1*       |        V1R2*       |
|:-------------------:|:------------------:|:------------------:|
|     `8.2 - 8.12`    | :heavy_check_mark: |         :x:        |
|     `8.14.x`        |         :x:        | :heavy_check_mark: |
|     `8.16.x`        |         :x:        | :heavy_check_mark: |

> [!NOTE]
> - \* Denotes STIG Readiness Guide   

## Overview
[Visit public.cyber.mil for the latest official releases](https://public.cyber.mil/stigs/)

This project contains content for compliance auditing and remediation of the VMware Aria Suite Lifecycle 8.x STIG Readiness Guide Baseline.

The VMware Aria Suite Lifecycle 8.x Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of VMware Aria Suite Lifecycle 8.x in the Department of Defense (DOD). The VMware Aria Suite Lifecycle 8.x STIG is comprised of the following:

- VMware Aria Operations 8.x STIG Readiness Guide
  - Application
  - NGINX
  - PostgreSQL
  - Photon OS

The VMware Aria Suite Lifecycle 8.x STIGs presume operation in an environment compliant with all applicable DOD guidance.

## Using this Repo
In each of these areas you will find instructions on how to run those components and other relevant notes. 

- docs - Supporting documentation will be made available here as needed.
- \<content version\>/ansible - Ansible Playbook for remediating controls.
- \<content version\>/inspec - InSpec profile for auditing controls.

## Disclaimer
VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License
The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
