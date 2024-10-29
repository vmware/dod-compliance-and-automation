# VMware vSphere 8 DOD STIG Compliance and Automation

## Compatibility
The table below provides supported interoperability between product and STIG versioning. Application of STIG content outside interoperable versions is not supported.

|      Version      |        V1R1*       |         V1R2*      |         V1R1       |         V2R1       |
|:-----------------:|:------------------:|:------------------:|:------------------:|:------------------:|
|     `8.0 GA`      |        :x:         |         :x:        |         :x:        |         :x:        |
|     `8.0 U1`      | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
|     `8.0 U1a`     | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
|     `8.0 U1b`     | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
|     `8.0 U1c`     | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
|     `8.0 U1d`     | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
|     `8.0 U1e`     | :heavy_check_mark: |         :x:        |         :x:        |         :x:        |
|     `8.0 U2`      |        :x:         | :heavy_check_mark: | :heavy_check_mark: |         :x:        |
|     `8.0 U2a`     |        :x:         | :heavy_check_mark: | :heavy_check_mark: |         :x:        |
|     `8.0 U2b`     |        :x:         | :heavy_check_mark: | :heavy_check_mark: |         :x:        |
|     `8.0 U2c`     |        :x:         | :heavy_check_mark: | :heavy_check_mark: |         :x:        |
|     `8.0 U2d`     |        :x:         | :heavy_check_mark: | :heavy_check_mark: |         :x:        |
|     `8.0 U3`      |        :x:         |        :x:         |        :x:         | :heavy_check_mark: |
|     `8.0 U3a`     |        :x:         |        :x:         |        :x:         | :heavy_check_mark: |
|     `8.0 U3b`     |        :x:         |        :x:         |        :x:         | :heavy_check_mark: |

> [!NOTE]
> - \* Denotes STIG Readiness Guide  
> - V1R2 of the STIG Readiness Guide is no longer available in favor of V1R1 of the Official STIG release  
> - Versioning in the table is based on vCenter. ESXi releases generally pair with vCenter but there are occasions where ESXi will skip a minor release. 

## Overview
[Visit public.cyber.mil for the latest official releases](https://public.cyber.mil/stigs/)

This project contains content for compliance auditing and remediation of the VMware vSphere 8 DOD STIG Baseline.

The VMware vSphere 8 Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of vSphere 8 in the Department of Defense (DOD). The vSphere 8 STIG is comprised of the following:

- VMware vSphere 8 STIG Readiness Guide
  - ESXi
  - Virtual Machine
  - vCenter (includes vSAN)
  - vCenter Server Appliance
    - EAM Service
    - Envoy
    - Lookup Service
    - Perfcharts Service
    - Photon OS
    - PostgreSQL
    - STS Service
    - UI Service
    - VAMI

The VMware vSphere 8 STIGs presume operation in an environment compliant with all applicable DOD guidance.

## Using this Repo
This repo is split up between controls for the vCenter Server Appliance(VCSA) and vSphere.  Within each of those areas are supporting auditing and remediation scripts.  

In each of those areas you will find instructions on how to run those components and other relevant notes.  

- docs - Supporting documentation will be made available here as needed.
- \<content version\>/vcsa - Content for the vCenter Server Appliance(VCSA)
- \<content version\>/vsphere - Content for vSphere(ESXi/VM/vCenter)

## Disclaimer
VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License
The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
