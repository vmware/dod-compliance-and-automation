# vmware-cloud-foundation-stig-baseline-operations-hcx
VMware Cloud Foundation Operations HCX 9.0 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 1  
Date: 17 June 2025  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance.  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine with network access to the target. Tested with version 6.8.24. Chef/CINC Workstation can also be installed and used.
- Running against a supported product version for this profile.
- The `vmware-cloud-foundation-stig-baseline` profile downloaded to a local folder on either Windows or Linux.

## Supported Versions
- VCF 9.0.0.0  

## Inputs
Inputs for an InSpec profile are sometimes needed to provide environment specific values in order for tests to run correctly. These can be provided by specifying an inputs file with the target environments values.  

An example inputs file is provided with in the parent folder and can be found in the `inputs-example.yml` file. This file can be reused, copied, or modified as needed.  

Below is a list of inputs available for this profile that can be provided.  

|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|`opshcx_deployed`  |`true`                     |Is Operations HCX deployed in the environment? Set to false to mark Operations HCX related rules N/A.|Boolean|All|
|`opshcx_url`       |`blank`                    |The target VCF Operations HCX URL IP or FQDN.|String|All|
|`opshcx_apiToken`  |`blank`                    |The session token for API authentication.|String|All|
|`opshcx_ntpServers`|`[]`                       |An array of authorized NTP servers.|Array|VCFA-9X-000383|

## Running InSpec/CINC-auditor

### How to get an API token
API credentials are needed to run an audit for VCF Operations HCX to support the Appliance API queries used in the audit.

Generate a base64 encoded string from the admin:password text.

Capture the value returned and enter this in the inputs file used for the value of the `opshcx_apiToken` input.

### Prepare inputs file
Provide the target environments inputs values in the inputs file to be used for the scan.

### Running the audit
The example commands below can be adapted to different environments and different paths as needed. 

**NOTE** If using CINC instead of InSpec, replace the `inspec` command with `cinc-auditor` for the best experience.  

Run the profile against a VCF Operations HCX target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/opshcx --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/opshcx/inputs-example.yml
```

Run the profile against a VCF Operations HCX target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI and JSON.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/opshcx --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/opshcx/inputs-example.yml --reporter=cli json:<path to report>.json
```

Run the profile against a VCF Operations HCX target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI but only audit a specific control.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/opshcx --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/opshcx/inputs-example.yml --controls VCFA-9X-000383
```

Run the profile against a VCF Operations HCX target, show progress, enable enhanced outcomes, provide inputs via an inputs file, specify a waiver file, and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/opshcx --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/opshcx/inputs-example.yml --waiver-file <path to>/waiver-example.yml
```

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into [MITRE's Heimdall](https://github.com/mitre/heimdall2) server for a more polished visual result.

## InSpec Vendoring
When a profile is ran, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.  

If any dependencies are added or updated that are in the `inspec.yml` file, run the `inspec vendor --overwrite` command to ensure the latest changes are used when running the profile.  
