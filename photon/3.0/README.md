# VMware Photon OS 3.0 STIG Compliance and Automation

## Overview
*STIG Status: STIG Readiness Guide independently and draft as included other product level STIGs such as vCenter 7.0.*

[Visit public.cyber.mil for the latest official releases](https://public.cyber.mil/stigs/)

This project contains content for compliance auditing and remediation of the VMware Photon OS 3.0 DoD STIG Baseline.

Note - Some content may be absent such as Vulnerability IDs for draft content and will be added once released by DISA  

The VMware Photon OS 3.0 Security Technical Implementation Guides (STIGs) provide security policy and configuration requirements for the use of Photon OS 3.0 in the Department of Defense (DoD). The Photon OS 3.0 STIG is based on the General Purpose Operating System (GPOS) SRG V1R6.

The VMware Photon OS 3.0 STIGs presume operation in an environment compliant with all applicable DoD guidance.

All technical NIST SP 800-53 requirements were considered while developing this content. SRG requirements that are applicable and configurable are included in the SRG content while other controls that are "Not Applicable", "Inherently Met" or "Does Not Meet" are not included.

## What is Photon OS?
Photon OS&trade; is an open source Linux container host optimized for cloud-native applications, cloud platforms, and VMware infrastructure. Photon OS provides a secure run-time environment for efficiently running containers. Some of the key highlights of Photon OS are:

- **Optimized for VMware hypervisor:** The Linux kernel is tuned for performance when Photon OS runs on VMware ESXi.

- **Support for containers:** Photon OS includes the Docker daemon and works with container orchestration frameworks, such as Mesos and Kubernetes.

- **Efficient lifecycle management:** Photon OS is easy to manage, patch, and update, using the [tdnf package manager](https://github.com/vmware/photon/blob/master/docs/photon-admin-guide.md#tiny-dnf-for-package-management) and the [Photon Management Daemon (pmd)](https://github.com/vmware/pmd).

- **Security hardened:** Photon OS provides secure and up-to-date kernel and other packages, and its policies are designed to govern the system securely.

For an overview of Photon OS, see [https://vmware.github.io/photon/](https://vmware.github.io/photon/)

## Photon OS Resources

- **Documentation**: The Photon OS [Documentation](https://vmware.github.io/photon/docs/) provides information about how to install, configure, and use VMware Photon OS™.
- **Security Updates**: Visit [Security-Advisories](https://github.com/vmware/photon/wiki/Security-Advisories).

## Using this Repo

This repo for Photon OS 3.0 is split up between auditing and remediation aspects with playbooks (Ansible) and profiles (InSpec).  

In each of those areas you will find instructions on how to run those components and other relevant notes.  

- docs - Supporting documentation will be made available here as needed.
- ansible - Ansible Playbook for remediating controls.
- inspec - InSpec profile for auditing controls.

## Disclaimer

VMware and DISA accept no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware and DISA implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License

The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
