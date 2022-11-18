![Lint Tests](https://github.com/vmware/dod-compliance-and-automation/actions/workflows/code-linting.yml/badge.svg?master)

# dod-compliance-and-automation

## Overview

VMware is a trusted partner in highly secure, mission critical systems around the world, including the US Department of Defense (DoD). In the DoD, all IT systems must adhere to the rigorous Risk Management Framework (RMF) as defined in DoDI 8510.01. A critical component of RMF is the mandatory implementation of Security Technical Implementation Guides (STIGs) and Security Requirements Guidelines (SRGs) as maintained by the Defense Information Systems Agency (DISA). Where a product specific STIG is not available, the relevant SRGs must be used instead.

[DoDI 8510.01](http://acqnotes.com/wp-content/uploads/2014/09/DoD-Instruction-8510.01-Risk-Management-Framework-RMF-for-DoD-Information-Technology-IT-24-May-2016.pdf)

>STIGs are product-specific and document applicable DoD policies and security
requirements, as well as best practices and configuration guidelines. STIGs are associated with
security controls through CCIs, which are decompositions of NIST SP 800-53 security controls
into single, actionable, measurable items. SRGs are developed by DISA to provide general
security compliance guidelines and serve as source guidance documents for STIGs. When a
STIG is not available for a product, an SRG may be used.

[DoD Cybersecurity Discipline
Implementation Plan](https://dodcio.defense.gov/Portals/0/Documents/Cyber/CyberDis-ImpPlan.pdf)

>STIGs and SRGs provide
configuration for technologies such as operating systems, browsers, antivirus, web services,
databases, Active Directory, and domain name services. The combination of applicable STIGs
and SRGs will result in a secure configuration to prevent issues such as insider threats, data
exfiltration, or advanced persistent threats.


In order to better serve the needs of our DoD partners, and those who wish to meet the bar set by the DoD, VMware is hereby providing three elements for community consumption and contribution.

* SRG Documentation
  * Raw SRG content that is either the source material for an existing or future STIG, or that can be used in place of a proper STIG.
* Auditing Automation
  * InSpec and PowerCLI content is provided to audit and report on the state of compliance for an associated set of SRG/STIG controls.
* Remediation Automation
  * Ansible and PowerCLI content is provided to programmatically help get the system into a compliant state.

## SRG Documentation

STIG development is essentially an exercise where a specific product is filtered through all applicable SRGs to produce product-specific, NIST 800-53 backed hardening guidance. That content is then vetted, tested and approved by the DISA Risk Management Executive (RME) and posted on iase.disa.mil and public.cyber.mil. VMware has a number of official STIGs published on those sites and we are working on many more. While we go through the official, lengthy DISA process, we want to make the SRG content available for public consumption and contributions while we wait for the official posting for products that are in process or are not scheduled to be submitted.

* Where a STIG is already published
  * The SRG documentation will be the official source content for the published STIG.
* Where a STIG is not published but the product is in the DISA queue
  * The SRG content will be in a usable, beta quality form from a VMware perspective
  * The content will not have any DISA review or approval, nor can we guarantee that any STIG will be published. We have very little influence over the DISA queue.
  * Please feel free to contact DISA RME if you would like to see the STIG request prioritized higher in their queue
  * https://public.cyber.mil/knowledge-base/scap-srg-stig-questions/
* Where a STIG is not published and the product is not in the DISA queue
  * Certain lower impact products may not ever realistically make it to the top of the DISA queue. In those cases, the SRG content will be provided in place of a STIG under the presumption that some guidance is better than none at all and referred to as a STIG Readiness Guide.

In all cases, the product's status in regards to the official STIG process will be noted at the top of the project README.md

__NOTE__: This project represents VMware's effort to document our compliance against the SRG requirements and nothing more. A published STIG is our eventual goal, in most cases, but this content should not be viewed to be "as good as a STIG". A DISA published STIG includes technical validation, review of requirement fulfillment, accuracy and style, risk acceptance and is digitally signed by the RME and posted on a .mil. This SRG content is intended to provided value to our partners while the STIGs are in process. Except for products that have published STIGs already, there is no explicit or implied DISA approval of the provided content.

## Compliance Automation

STIG documents are written to be portable, offline hardening documentation where a sysadmin can go through, step by step, and STIG a system with no external dependencies. That said, many STIGs are either too complex or need to be applied to so many instances that manual steps are just not feasible. To augment the plain language STIG content, we are providing a number of ways to script or fully automate your VMware compliance activities.

### Auditing with InSpec

The role of STIG assessment automation is traditionally filled by SCAP with OVAL. VMware has looked at providing SCAP and OVAL content but we decided to move forward with [InSpec](https://www.inspec.io/) for a number of reasons including, but not limited to, the following:

* Speed of development, low time to value
* Ease of use, readability
* Agentless
* Active community
* Backed by Mitre with [STIG-specific tooling](https://github.com/mitre/inspec_tools)
* Appropriate for open source
* Flexibility, extensibility
* DevSecOps friendly

We may elaborate on these points in the future but the decision was not a difficult one. A blog post covering InSpec basics will be forthcoming.

### Remediation with Ansible

[Ansible](https://www.ansible.com/overview/how-ansible-works) is a relatively simple, extremely powerful IT automation platform. It's benefits are well documented and very similar to those listed for InSpec above. We are providing Ansible remediation content in order to integrate with existing configuration management systems.

### Auditing and Remediation with PowerCLI

[PowerCLI](https://code.vmware.com/web/dp/tool/vmware-powercli/) is an extension of Microsoft's PowerShell that is provided by VMware free of charge for automating virtual infrastructure. PowerCLI can be deployed on Windows or Linux operating systems and can reach out remotely to query and configure VMware product installations.

## Documentation

Depending on the product, there may be a need to host DoD specific whitepapers, notes and addendums that have no other appropriate place. These items will be provided under the docs path where applicable.

## Contributing

The dod-compliance-and-automation project team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).

* __SRG Content__ - VMware owns the state of the SRG/STIG controls provided here, including their applicability and how the requirements are addressed. That said, we are open to ideas for further hardening, additional methods, refinements, expansion, etc.

* __Automation Content__ - VMware provides the automation content in a beta complete state. Once it is used by the broad github audience, we expect the need for refinements and we highly encourage feedback and direct contributions.

## License

The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
