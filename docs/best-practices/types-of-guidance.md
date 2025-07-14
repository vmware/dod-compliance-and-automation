# Types of Guidance
For more information on the different types of STIG guidance VMware offers see the [VMware STIG Program Overview](https://www.vmware.com/docs/vmw-stig-program-overview).

## Overview
VMware is a trusted partner in highly secure, mission critical systems around the world, including the US Department of Defense (DOD). In the DOD, all IT systems must adhere to the rigorous Risk Management Framework (RMF) as defined in `DoDI 8510.01`. A critical component of RMF is the mandatory implementation of Security Technical Implementation Guides (STIGs) and Security Requirements Guidelines (SRGs) as maintained by the Defense Information Systems Agency (DISA). To serve VMware Cloud Foundation customers in the DOD, as well as others who wish to meet the bar set by the DOD, VMware actively engages with DISA to produce and publish STIGs through their vendor STIG development process.  

## What is a STIG/SRG?
Here is how these terms are defined in `DoDI 8510.01`:  

*STIGs are product-specific and document applicable DoD policies and security requirements, as well as best practices and configuration guidelines. STIGs are associated with security controls through CCIs, which are decompositions of NIST SP 800-53 security controls into single, actionable, measurable items. SRGs are developed by DISA to provide general security compliance guidelines and serve as source guidance documents for STIGs. When a STIG is not available for a product, an SRG may be used.*

A STIG in VMware terms is a product specific hardening guide based on security requirements from the DOD that contains detailed and comprehensive steps to audit and remediate the requirements that have actionable configurations associated with them.  

An SRG, on the other hand, is a collection of requirements applicable to a given technology family, product category, or organization in general. They are non-product specific requirements used to mitigate common security vulnerabilities encountered across information technology systems and applications. SRGs are the source documents developed by DISA from which a STIG is derived. SRGs come in a number of broad categories such as "Web Server" and "Database". The process of creating a STIG is largely determining what SRG(s) apply to a product and addressing those requirements.  

## Official STIGs vs. STIG Readiness Guides
Official STIGs are published by DISA on public.cyber.mil. VMware products must go through the vendor STIG development process mentioned previously to have an official STIG published.  In many instances, even though there may be customer demand for STIG content for a product well before the STIG development process completes, due to resourcing or time constraints, the STIG publication may not happen at all. In some of these cases VMware may make available a “STIG Readiness Guide”. This means that the same level of work is being performed as would normally occur with DISA but VMware is self-publishing the content to make it available and usable as soon as possible. The quality is high enough, from past experience, that should a given “STIG Ready” product be put through the DISA process, there is a high level of confidence that there would be minimal content changes before publication.  

These guides represent VMware's effort to document compliance against the SRG requirements and nothing more. A published STIG is the eventual goal, in most cases, but this content should not be viewed to be "as good as a STIG". A DISA published STIG includes technical validation, review of requirement fulfillment, accuracy and style, risk acceptance, and is digitally signed by the DISA Risk Management Executive. Except for products that already have published STIGs, there is no explicit or implied DISA approval of the provided content other than their guidance allows for such content to be used in the absence of an official STIG. We also make no guarantee that any STIG(s) will be published from this content in the future.  

## STIG Readiness Guides
We are often asked by our DOD customers if our STIG Readiness Guides can be used? The answer is yes.  

In the absence of a STIG a DoD customer must fall back to SRGs to harden their environments as written in `DoDI 8510.01`.

*"When a STIG is not available for a product, an SRG may be used."*  

Figuring out how these generic requirements are met for products (frequently with very little documentation available to aid in the research) is often a daunting task for a customer.  

DISA further elaborates on this issue in their FAQ here: https://public.cyber.mil/stigs/faqs/#toggle-id-10  

**What do I use if there is no STIG?**
*First determine if a STIG has been published for an earlier version of the same product. Many checks and fixes in earlier versions of STIGs can be applied to the new version of the product. If a STIG for an older version of the product is available, review the check and fix procedures to determine which of these work with the new product version. Where possible, use the checks and fixes that work directly with the new version. The remainder of checks and fixes that no longer work with the new product version will need to be evaluated and proper check and fix procedures will need to be determined for each requirement. New product features and configuration settings must also be accounted for based on the relevant SRG.*

*If there is no related STIG, the most relevant SRG can be used to determine compliance with DoD policies. If assistance is needed in determining which SRG applies to the product, please open a ticket with the STIG Customer Support Helpdesk at disa.stig_spt@mail.mil In fulfilling a requirement, be it from an SRG or an earlier version of a STIG, vendor documentation may be followed for configuration guidance.*

Using this information, VMware is able to provide STIG Readiness Guides for use in order to alleviate the burden of trying to carry old STIGs forward to newer product versions or analyzing SRGs.  
