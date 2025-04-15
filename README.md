![Linting](https://github.com/vmware/dod-compliance-and-automation/actions/workflows/code-linting-push.yml/badge.svg?master)
![Docs Deployment](https://github.com/vmware/dod-compliance-and-automation/actions/workflows/deploy-docs.yml/badge.svg?docs)
# dod-compliance-and-automation

> [!CAUTION]
> Prior to using the STIG automation provided here it is assumed the user has familiarity with the rules contained in the various VMware STIGs and has evaluated those for impact and implementation considerations in their environment.

## Announcements
Please visit our new documentation page at: https://vmware.github.io/dod-compliance-and-automation/  

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

In order to better serve the needs of our DoD partners, and those who wish to meet the bar set by the DoD, VMware is providing three elements for community consumption and contribution.

* STIG Readiness Guides
  * SRG based content that is either the source material for an in process STIG, or that can be used in the absence of an official STIG.
* Auditing Automation
  * Automation to audit and report on the state of compliance for an associated set of SRG/STIG controls.
* Remediation Automation
  * Automation to remediate findings with a set of SRG/STIG controls using publicly accessible methods and APIs.

## STIG Readiness Guides
STIG development is essentially an exercise where a specific product is filtered through all applicable SRGs to produce product-specific, NIST 800-53 backed hardening guidance. That content is then vetted, tested and approved by the DISA Risk Management Executive (RME) and posted on public.cyber.mil. VMware has a number of official STIGs published and we are working on many more. While we go through the official DISA vendor process, we want to make the SRG content available for public consumption and contributions while we wait for the official posting for products that are in process or are not scheduled to be submitted.

For more information on STIG Readiness Guides please read about our [STIG program](https://www.vmware.com/docs/vmw-stig-program-overview).

__NOTE__: This project represents VMware's effort to document our compliance against the SRG requirements and nothing more. A published STIG is our eventual goal, in most cases, but this content should not be viewed to be "as good as a STIG". A DISA published STIG includes technical validation, review of requirement fulfillment, accuracy and style, risk acceptance and is digitally signed by the RME and posted on a .mil. This SRG content is intended to provided value to our partners while the STIGs are in process. Except for products that have published STIGs already, there is no explicit or implied DISA approval of the provided content.

## Compliance Automation
STIG documents are written to be portable, offline hardening documentation where a sysadmin can go through, step by step, and STIG a system with no external dependencies. That said, many STIGs are either too complex or need to be applied to so many instances that manual steps are just not feasible. To augment the plain language STIG content, we are providing a number of ways to script or fully automate your VMware compliance activities.

## Repo Structure
Automation provided here will be in the following structured format:  

* Product
  * Major Version
    * README
    * docs
    * STIG Content Version

For example:
* vsphere
  * 8.0
    * README
    * docs
    * v1r1-srg
    * v1r1-stig

*`srg` will denote STIG Readiness Guide content and `stig` will denote official STIG content*

## Documentation
Depending on the product, there may be a need to host DOD specific whitepapers, notes and addendums that have no other appropriate place. These items will be provided under the docs path where applicable.

## Support
More information on support for STIGs and STIG Readiness Guides is available in the [Support](SUPPORT.md) document.

## Archives
The `master` branch in this repo will contain only content for currently supported products. Access to older revisions of guidance and automation for products that are no longer supported and End of Life(EoL) will be available in the `archived_content` branch.  

## Contributing
The dod-compliance-and-automation project team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).

* __STIG Readiness Guides Content__ - VMware owns the state of the SRG/STIG controls provided here, including their applicability and how the requirements are addressed. That said, we are open to ideas for further hardening, additional methods, refinements, expansion, etc.

* __Automation Content__ - VMware provides the automation content in a beta complete state. Once it is used by the broad github audience, we expect the need for refinements and we highly encourage feedback and direct contributions.

## Disclaimer
VMware accepts no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License
The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
