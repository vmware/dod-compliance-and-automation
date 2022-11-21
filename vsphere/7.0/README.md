# VMware vSphere 7.0 DoD STIG Compliance and Automation

## Overview
*STIG Status: In process with DISA, STIG Readiness Guide v1r4*

[Visit public.cyber.mil for the latest official releases](https://public.cyber.mil/stigs/)

This project contains content for compliance auditing and remediation of the VMware vSphere 7.0 DoD STIG Baseline.

Note - Some content may be absent such as Vulnerability IDs for draft content and will be added once released by DISA  

The VMware vSphere 7.0 Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of vSphere 7.0 in the Department of Defense (DoD). The vSphere 7.0 STIG is comprised of the following:

- VMware vSphere 7.0 STIG
  - ESXi
  - Virtual Machine
  - vCenter (includes vSAN)
  - vCenter Server Appliance
    - EAM Service
    - Lookup Service
    - Perfcharts Servce
    - PostgreSQL
    - Reverse Proxy
    - STS Service
    - VAMI
    - vSphere UI Service

The VMware vSphere 7.0 STIGs presume operation in an environment compliant with all applicable DoD guidance.

All technical NIST SP 800-53 requirements were considered while developing this STIG. SRG requirements that are applicable and configurable are included in the SRG content spreadsheets and will be included in the final STIG. Other controls that are "Not Applicable", "Inherently Met" or "Does Not Meet" are not included, here or in the final STIG.

## Using this Repo

This repo for 7.0 is split up between controls for the vCenter Server Appliance (vcsa) and vSphere.  Within each of those areas are supporting auditing and remediation scripts (PowerCLI), playbooks (Ansible), and profiles (InSpec).  

In each of those areas you will find instructions on how to run those components and other relevant notes.  

- docs - Supporting documentation will be made available here as needed.
- vcsa - Content for the vCenter Server Appliance (VCSA)
- vsphere - Content for vSphere (ESXi/VM/vCenter)

## Disclaimer

VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License

The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
