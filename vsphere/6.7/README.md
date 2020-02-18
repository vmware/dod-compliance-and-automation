# VMware vSphere 6.7 DoD STIG Compliance and Automation

## Contents
- [Overview](#overview)
- [Using this Repo](#using-this-repo)
- [Docs](#docs)
- [Severities](#severties)
- [Disclaimer](#disclaimer)
- [License](#license)

## Overview
Content for compliance auditing and remediation of the VMware vSphere 6.7 DoD STIG Baseline.

Current version: **Draft vSphere 6.7 STIG**  

Note - Some content may be absent such as Vulnerability IDs for draft content and will be added once released by DISA  

[Visit public.cyber.mil for the latest official releases](https://public.cyber.mil/stigs/)

The VMware vSphere 6.7 Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of vSphere 6.7 in the Department of Defense (DoD). The following comprise the VMware vSphere 6.7 STIGs:

- **VMware vSphere 6.7 ESXi STIG**
- **VMware vSphere 6.7 Virtual Machine STIG**
- **VMware vSphere 6.7 Appliance Photon OS STIG**
- **VMware vSphere 6.7 Appliance VAMI STIG**
- **VMware vSphere 6.7 Appliance PostgreSQL STIG**
- **VMware vSphere 6.7 Appliance EAM STIG**
- **VMware vSphere 6.7 Appliance Perfcharts STIG**
- **VMware vSphere 6.7 Appliance STS STIG**
- **VMware vSphere 6.7 Appliance vSphere UI STIG**
- **VMware vSphere 6.7 Appliance vSphere Client STIG**
- **VMware vSphere 6.7 Appliance rhttpproxy STIG**
- **VMware vSphere 6.7 vCenter Server for Windows STIG**

The VMware vSphere 6.7 STIGs presume operation in an environment compliant with all applicable DoD guidance.

All technical NIST SP 800-53 requirements were considered while developing this STIG. Requirements that are applicable and configurable will be included in the final STIG.

## Using this Repo

This repo for 6.7 is split up between controls for the vCenter Server Appliance (vcsa) and vSphere.  Within each of those areas are supporting auditing and remediation scripts (PowerCLI), playbooks (Ansible), and profiles (Inspec).  

In each of those areas you will find instructions on how to run those components and other relevant notes.  

## Docs

Supporting documentation will be here such as smartcard configuration guides, srg spreadsheets, etc.

## Severities

Severity Category Codes (referred to as CAT) are a measure of vulnerabilities used to assess a facility or system security posture. Each security policy specified in this document is assigned a Severity Category Code of CAT I, II, or III.

- CAT I Any vulnerability, the exploitation of which will directly and immediately result in loss of Confidentiality, Availability, or Integrity.
- CAT II Any vulnerability, the exploitation of which has a potential to result in loss of Confidentiality, Availability, or Integrity.
- CAT III Any vulnerability, the existence of which degrades measures to protect against loss of Confidentiality, Availability, or Integrity.

## Disclaimer

VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level due to the fact that some of the settings may not be able to be configured in environments outside the DoD architecture.

## License

The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
