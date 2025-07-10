
For the most up to date information on support please visit our STIG Support KB: https://knowledge.broadcom.com/external/article?legacyId=94398

## Table of contents

- [Types of Support](#types-of-support)
- [Unsupported Scenarios](#unsupported-scenarios)
- [Automation Support](#automation-support)
- [Official STIG Support](#official-stig-support)
- [STIG Readiness Guide Support](#stig-readiness-guide-support)
- [Support Tips](#support-tips)
- [Disclaimer](#disclaimer)

## Types of Support

**Automation Support:** Issues related to running scripts, playbooks, etc. found in this repository.

**Content Support:** Problems with the guidance text found in a STIG.  
Examples:
- Clarification on guidance text
- A command does not work as expected
- Typos in the text
- Check/Fix update suggestions

**Product Support:** Break/fix bug type issues encountered when using features and functionality found inside a STIG's content.  
Examples:
- Enabling Secureboot causes a host not to boot.
- Hardening a service causes it to not start.

## Unsupported Scenarios
- Content and product version mismatched. For example applying the vSphere 7 STIG to vSphere 8.
- Attempting to apply guidance from one STIG to a product it was not intended for.
- A product that is no longer generally supported by VMware. See the [VMware Product Lifecycle Matrix](https://lifecycle.vmware.com/) for product end of general support dates.


## Automation Support

Support for automation found in this repo is community based and provided on a best effort basis.  

If an issue is encountered please check the [open](https://github.com/vmware/dod-compliance-and-automation/issues) and [closed](https://github.com/vmware/dod-compliance-and-automation/issues?q=is%3Aissue+is%3Aclosed) issues in the issue tracker for the details of your issue. If you can't find it, or if you're not sure, open a new issue.

A known issues document may also be available for a product and version in that product's docs folder in this repository.

## Official STIG Support

**Content Support**

Support for issues related to content in an Official STIG should be addressed by emailing DISA at: disa.stig_spt@mail.mil  

A ticket for the issue must be open in order to update the guidance in a future STIG release. DISA will work with VMware to address any tickets needing content updates as necessary.

**Product Support**

A support request may be opened in these cases if a valid support agreement is in place.

## STIG Readiness Guide Support

**Content Support**

Support for issues related to content in a STIG Readiness Guide should be addressed by emailing: stigs@broadcom.com 

Requests received will be processed on a best effort basis and any needed content updates will be published in the next content release. In between releases, issues will be documented in a known issues document available in a product's docs folder in this repository.  

**Product Support**

A support request may be opened in these cases if a valid support agreement is in place.

## Support Tips

Before contacting support consider the following:

- Is this a known issue?
- Does reverting the change restore functionality?
- Provide the source of the guidance with version and target product version in the request.
- Is this a supported scenario as laid out in this document?
- Support cannot assist with implementation of any hardening guidance or provide security advice.

## Disclaimer

VMware accepts no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations may use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.
