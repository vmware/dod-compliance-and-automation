# VMware Cloud Director 10.x DOD STIG Compliance and Automation

## Compatibility
The table below provides supported interoperability between product and STIG versioning. Application of STIG content outside interoperable versions is not supported.

|      Version      |        V1R1*       |        V1R2*       |
|:-----------------:|:------------------:|:------------------:|
|      `10.4`       | :heavy_check_mark: |         :x:        |
|      `10.4.1`     | :heavy_check_mark: |         :x:        |
|      `10.4.1.1`   | :heavy_check_mark: |         :x:        |
|      `10.4.2`     | :heavy_check_mark: |         :x:        |
|      `10.4.2.1`   | :heavy_check_mark: |         :x:        |
|      `10.4.2.2`   | :heavy_check_mark: |         :x:        |
|      `10.4.3  `   | :heavy_check_mark: |         :x:        |
|      `10.5`       | :heavy_check_mark: |         :x:        |
|      `10.5.1`     | :heavy_check_mark: |         :x:        |
|      `10.5.1.1`   | :heavy_check_mark: |         :x:        |
|      `10.6.1`     |        :x:         | :heavy_check_mark: |

> [!NOTE]
> - \* Denotes STIG Readiness Guide  

## Overview
This project folder contains content for compliance auditing and remediation of the VMware Cloud Director 10.x STIG Readiness Guide.

The VMware Cloud Director Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of VMware Cloud Director 10.x in the Department of Defense (DOD). The VMware Cloud Director 10.x STIG is comprised of the following:

- VMware Cloud Director 10.x STIG 
  - VCD Application
  - VCD Appliance
    - NGINX
    - Photon OS 4.0
    - PostgreSQL

The VVMware Cloud Director 10.x STIGs presume operation in an environment compliant with all applicable DOD guidance.

## Using this Repo
In each of these areas you will find instructions on how to run those components and other relevant notes.  
- docs - Supporting documentation will be made available here as needed.
- \<content version\>/ - Automation Content

## Disclaimer
VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License
The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
