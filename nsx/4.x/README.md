# VMware NSX 4.x STIG Compliance and Automation

## Compatibility
The table below provides supported interoperability between product and STIG versioning. Application of STIG content outside interoperable versions is not supported.

|      Version      |        V1R1*       |        V1R2*       |        V1R1       |
|:-----------------:|:------------------:|:------------------:|:------------------:|
|     `4.1.0`       | :heavy_check_mark: |         :x:        |         :x:        |
|     `4.1.0.2`     | :heavy_check_mark: |         :x:        |         :x:        |
|     `4.1.1`       | :heavy_check_mark: |         :x:        |         :x:        |
|     `4.1.2`       |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
|     `4.1.2.1`     |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
|     `4.1.2.3`     |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
|     `4.1.2.4`     |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
|     `4.1.2.5`     |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
|     `4.2.0.0`     |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
|     `4.2.0.1`     |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
|     `4.2.0.2`     |         :x:        | :heavy_check_mark: | :heavy_check_mark: |
|     `4.2.1.0`     |         :x:        | :heavy_check_mark: | :heavy_check_mark: |

> [!NOTE]
> - \* Denotes STIG Readiness Guide   

## Overview
[Visit public.cyber.mil for the latest official releases](https://public.cyber.mil/stigs/)

This project contains content for compliance auditing and remediation of the VMware NSX 4.x STIG Readiness Guide Baseline.

The VMware NSX 4.x Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of VMware NSX 4.x in the Department of Defense (DOD). The VMware NSX 4.x STIG is comprised of the following:
- VMware NSX 4.x STIG Readiness Guide
  - Distributed Firewall
  - Manager
  - Tier-0 Gateway Firewall
  - Tier-0 Gateway Router
  - Tier-1 Gateway Firewall
  - Tier-1 Gateway Router

The VMware NSX 4.x STIGs presume operation in an environment compliant with all applicable DOD guidance.

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
