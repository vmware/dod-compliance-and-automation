# vmware-cloud-foundation-stig-baseline
VMware Cloud Foundation 9.1 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 2  
Updated: 2026-05-12  
STIG Release: Y26M05  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This repository represents a collection of compliance auditing profiles that are based on [Chef InSpec](https://downloads.chef.io/tools/inspec)/[CINC Auditor](https://cinc.sh/start/auditor/) to perform an automated audits for STIG compliance of VMware Cloud Foundation product based rules. These profiles are intended to be ran individually for each VCF component. 

## Supported Versions
- VCF 9.1.0.0  

## Support
- These profiles have not been tested for forward or backward compatibility beyond the version of VCF listed.  
- For more information on general STIG support, please see the [Support for Security Technical Implementation Guides](https://knowledge.broadcom.com/external/article?legacyId=94398) KB article.  

## Which STIGs are covered?
VMware Cloud Foundation Application STIG  
* automation
* operations
* opshcx
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
  * routing  
