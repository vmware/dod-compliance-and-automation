

# dod-compliance-and-automation

## Overview

VMware is a trusted partner in highly secure, mission critical systems around the world, including the US Department of Defense (DoD). In the DoD, all IT systems must adhere to the rigorous Risk Management Framework (RMF) as defined in DoDI 8510.01. A critical component of RMF is the mandatory implementation of Security Technical Implementation Guides (STIGs) and Security Requirements Guidelines (SRGs) as maintained by the Defense Information Systems Agency (DISA). Where a product specific STIG is not available, the relevant SRGs must be used instead.

"STIGs are product-specific and document applicable DoD policies and security
requirements, as well as best practices and configuration guidelines. STIGs are associated with
security controls through CCIs, which are decompositions of NIST SP 800-53 security controls
into single, actionable, measurable items."

"SRGs are developed by DISA to provide general
security compliance guidelines and serve as source guidance documents for STIGs."

"STIGs and SRGs provide
configuration for technologies such as operating systems, browsers, antivirus, web services,
databases, Active Directory, and domain name services. The combination of applicable STIGs
and SRGs will result in a secure configuration to prevent issues such as insider threats, data
exfiltration, or advanced persistent threats."

https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/851001_2014.pdf
https://dodcio.defense.gov/Portals/0/Documents/Cyber/CyberDis-ImpPlan.pdf

In order to better serve the needs of our DoD partners, and those who wish to meet the bar set by the DoD, VMware is providing STIG and SRG documentation as well as compliance auditing and remediation code for community consumption and contribution.

## SRG Documentation

STIG development is essentially an exercise where a specific product is filtered through all applicable SRGs to produce product-specific, NIST 800-53 backed hardening guidance. That content is then vetted, tested and approved by the DISA Risk Management Executive (RME) and posted on iase.disa.mil and public.cyber.mil. VMware has a number of official STIGs published on those sites and we are working on many more. While we go through the official, lengthy DISA process, we want to make the SRG content available for public consumption versus while we wait for the official posting.

* Where a STIG is already published
 * The SRG documentation will be the official source content for the published STIG.
* Where a STIG is not published but the product is in the DISA queue
 * The SRG content will be in a usable, beta quality form from a VMware perspective
 * The content will not have any DISA review or approval, nor can we guarantee that any STIG will be published. We have very little influence over the DISA queue.
 * Please feel free to contact DISA RME if you would like to see the STIG request prioritized higher in their queue
  * https://public.cyber.mil/knowledge-base/scap-srg-stig-questions/
* Where a STIG is not published and the product is not in the DISA queue
 * Certain lower impact products may not ever realistically make it to the top of the DISA queue. In those cases, the SRG content will be provided in place of a STIG because some guidance is better than none at all.

In all cases, the product's status in regards to the official STIG process will be noted at the top of the project README.md

While DISA RME has approved of this SRG content publication concept, the content itself is not in any way approved by DISA. This project represents VMware's effort to document our compliance against the SRG requirements and nothing more. A published STIG is our eventual goal, in most cases, but this content should not be viewed to be "as good as a STIG". A DISA published STIG includes technical validation, review for accuracy and style, risk acceptance and is digitally signed by the RME and posted on a .mil. This SRG content is intended to provided value to our customers while the STIGs are in process.

## Compliance Automation

STIG documents are written to be portable, offline hardening documentation where a sysadmin can go through, step by step, and STIG a system with no external dependencies. That said, many STIGs are either too complex or need to be applied to so many instances that manual steps are not an ideal solution. To augment the plain language STIG content, we are providing a number of ways to script or fully automate your VMWare compliance activities.

### Auditing and Remediation with PowerCLI

### Auditing with InSpec

The role of STIG assessment automation is traditionally filled by SCAP with OVAL. VMware has looked as providing SCAP and OVAL content but we decided to move forward with InSpec for a number of reasons including, but not limited to, the following:

* Simplicity
* Agentless
* Active community
* Backed by Mitre
* Appropriate for open source
* Extensibility

We may elaborate on these points in the future but the decision was not a difficult one. A blog post covering InSpec basics will be forthcoming.

### Remediation with Ansible

### Prerequisites

* Prereq 1
* Prereq 2
* Prereq 3

### Build & Run

1. Step 1
2. Step 2
3. Step 3

## Documentation

## Contributing

The dod-compliance-and-automation project team welcomes contributions from the community. Before you start working with dod-compliance-and-automation, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License
