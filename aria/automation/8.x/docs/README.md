# VMware Aria (formerly vRealize Automation) 8.12 STIG Documentation

## Compatibility
This STIG Readiness Guide Version 1 Release 4 is intended for versions 8.12 and 8.13 only. If you are still on version 8.11 or earlier please reference the guidance available [here](https://github.com/vmware/dod-compliance-and-automation/tree/e2df6ab7ed8cd72148ede03fed97d894885fe95c/aria/automation/8.x). If you are on version 8.13.1 or later, new STIG Readiness Guides are in development for those versions.

|                     |        V1R3*       |         V1R4*      |
|:-------------------:|:------------------:|:------------------:|
|  8.6 GA to 8.11 GA  | :heavy_check_mark: |         :x:        |
|  8.12 GA to 8.13 GA |         :x:        | :heavy_check_mark: |
|      8.13.1 GA      |         :x:        |         :x:        |

\* Denotes STIG Readiness Guide  

## Overview
An XCCDF formatted XML is provided for the Aria Automation STIG Readiness Guide content for each component for use to view in the DISA [STIG Viewer](https://public.cyber.mil/stigs/stig-viewing-tools/).  

The zip file here can be directly imported into the DISA STIG Viewer for review and checklist creation.

This project folder contains content for compliance auditing and remediation of the VMware Aria Automation STIG Readiness Guide.

The VMware Aria Automation Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of VMware Aria Automation in the Department of Defense (DoD). The VMware Aria Automation STIG is comprised of the following:

- VMware Aria Automation STIG 
  - VMware Aria Automation Application
  - VMware Aria Automation Appliance
    - Docker
    - Kubernetes
    - Photon OS 3.0

The VMware Aria Automation STIGs presume operation in an environment compliant with all applicable DoD guidance.

All technical NIST SP 800-53 requirements were considered while developing this STIG. SRG requirements that are applicable and configurable are included in the SRG content spreadsheets. Other controls that are "Not Applicable", "Inherently Met" or "Does Not Meet" are not included.

## Using this Repo

In each of these areas you will find instructions on how to run those components and other relevant notes.  
- docs - Supporting documentation will be made available here as needed.
- inspec - Automation for auditing VMware Aria Automation for compliance.

## Disclaimer

VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License

The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).