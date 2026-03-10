# vmware-cloud-foundation-stig-baseline
VMware Cloud Foundation 9.0 STIG Readiness Guide Chef InSpec Profile  
Updated: 2025-06-17  
STIG Release: Y25M06  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This repository represents a collection of compliance auditing profiles that are based on [Chef InSpec](https://downloads.chef.io/tools/inspec)/[CINC Auditor](https://cinc.sh/start/auditor/) to perform an automated audits for STIG compliance of VMware Cloud Foundation product based rules. These profiles are intended to be ran individually for each VCF component. 

## Supported Versions
- VCF 9.0.0.0  

## Support
- These profiles have not been tested for forward or backward compatibility beyond the version of VCF listed.  
- For more information on general STIG support, please see the [Support for Security Technical Implementation Guides](https://knowledge.broadcom.com/external/article?legacyId=94398) KB article.  

## Which STIGs are covered?
VMware Cloud Foundation Application STIG  
* automation
* operations
* opsfm
* opshcx
* opslogs
* opsnet
* sddcmgr
* vsphere
  * vcenter  

VMware Cloud Foundation ESX STIG  
* vsphere
  * esx  

VMware Cloud Foundation Virtual Machine STIG  
* vsphere
  * vm  

VMware Cloud Foundation NSX Manager STIG  
* nsx
  * manager  

VMware Cloud Foundation NSX Gateway Routing STIG  
* nsx
  * gateway  
