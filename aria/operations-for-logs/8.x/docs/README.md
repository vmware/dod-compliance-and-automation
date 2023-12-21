# VMware Aria Operations for Logs 8.14 STIG Readiness Guide Documentation

## Compatibility
This STIG Readiness Guide *Version 1 Release 3* is intended for version 8.14. If you are on a previous version please reference the guidance available [here](https://github.com/vmware/dod-compliance-and-automation/tree/f81b17bc4527711969af024ae53ab70180ef1c59/aria/operations-for-logs/8.x).

|                     |        V1R2*       |        V1R3*       |
|                     | (previous release) |   (this release)   |
|:-------------------:|:------------------:|:------------------:|
|  8.12 GA to 8.13 GA | :heavy_check_mark: |         :x:        |
|       8.14 GA       |         :x:        | :heavy_check_mark: |

\* Denotes STIG Readiness Guide

## Overview
An XCCDF formatted XML is provided for the VMware Aria Operations for Logs STIG Readiness Guide content for each component for use to view in the DISA [STIG Viewer](https://public.cyber.mil/stigs/stig-viewing-tools/).  

The zip file here can be directly imported into the DISA STIG Viewer for review and checklist creation.

This project folder contains content for compliance auditing of the VMware Aria Operations for Logs STIG Readiness Guide.

The VMware Aria Operations for Logs Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for use in the Department of Defense (DoD). The STIG Readiness Guide is comprised of the following:

- VMware Aria Operations for Logs STIG Readiness Guide
  - Application controls
  - Cassandra controls
  - tc Server controls
  - Photon OS 4.0 controls

The VMware Aria Operations for Logs STIG Readiness Guide presumes operation in an environment compliant with all applicable DoD guidance.

All technical NIST SP 800-53 requirements were considered while developing this content. SRG requirements that are applicable and configurable are included. Other controls that are "Not Applicable", "Inherently Met" or "Does Not Meet" are not included.

## Using this Repo

In each of these areas you will find instructions on how to run the components and other relevant notes.  
- docs - Supporting documentation will be made available here as needed.
- inspec - Automation for auditing VMware Aria Operations for Logs for compliance.

## Disclaimer

Neither VMware nor DISA accept liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, neither VMware nor DISA imply any warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License

The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).