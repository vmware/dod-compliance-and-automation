# VMware Cloud Foundation 5.x DOD STIG Compliance and Automation

## Compatibility
The table below provides supported interoperability between product and STIG versioning. Application of STIG content outside interoperable versions is not supported.

|      Version      |        V1R1*       |         V1R2*      |
|:-----------------:|:------------------:|:------------------:|
|     `5.0.0.0`     | :heavy_check_mark: |         :x:        |
|     `5.0.0.1`     | :heavy_check_mark: |         :x:        |
|     `5.1.0.0`     |         :x:        | :heavy_check_mark: |

> [!NOTE]
> - \* Denotes STIG Readiness Guide    

## Overview
This project folder contains content for compliance auditing and remediation of the VMware Cloud Foundation 5.x STIG Readiness Guide.

The VMware Cloud Foundation 5.x Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of VMware Cloud Foundation 5.x in the Department of Defense (DOD). The VMware Cloud Foundation 5.x STIG is comprised of the following:

- VMware Cloud Foundation 5.x STIG 
  - SDDC Manager Application
  - SDDC Manager Appliance
    - Common Services Service
    - Domain Manager Service
    - Lifecycle Manager Service
    - NGINX
    - Operations Manager Service
    - Photon OS
    - PostgreSQL
    - SOS Service
    - UI Service

The VMware Cloud Foundation 5.x STIGs presume operation in an environment compliant with all applicable DOD guidance.

## Using this Repo
This repo only covers the SDDC Manager. vSphere and NSX content can be found in their respective repos.  

In each of these areas you will find instructions on how to run those components and other relevant notes.  
- docs - Supporting documentation will be made available here as needed.
- \<content version\>/inspec - Automation for auditing SDDC Manager for compliance.
- \<content version\>/ansible - Automation for remediating SDDC Manager.

## Disclaimer
VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License
The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
