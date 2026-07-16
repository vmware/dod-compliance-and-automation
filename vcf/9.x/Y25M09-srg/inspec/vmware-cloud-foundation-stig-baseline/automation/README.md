# vmware-cloud-foundation-stig-baseline-automation
VMware Cloud Foundation Automation 9.0 STIG Readiness Guide Chef InSpec Profile  
Version: Release 1 Version 1  
Date: 17 June 2025  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance.  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine with network access to the target. Tested with version 6.8.24. Chef/CINC Workstation can also be installed and used.
- Running against a supported product version for this profile.
- An API session token
- The `vmware-cloud-foundation-stig-baseline` profile downloaded to a local folder on either Windows or Linux.

## Supported Versions
- VCF 9.0.0.0  

## Inputs
Inputs for an InSpec profile are sometimes needed to provide environment specific values in order for tests to run correctly. These can be provided by specifying an inputs file with the target environments values.  

An example inputs file is provided with in the parent folder and can be found in the `inputs-example.yml` file. This file can be reused, copied, or modified as needed.  

Below is a list of inputs available for this profile that can be provided.  

|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|`automation_deployed`|`true`                     |Is VCF Automation deployed in the environment? Set to false to mark VCF Automation related rules N/A.|Boolean|All|
|`automation_url`     |`blank`                    |The target VCF Automation URL IP or FQDN.|String|All|
|`automation_sessionToken`|`blank`                |The session token for API authentication.|String|All|
|`automation_apiVersion`|`application/*;version=40.0`|The API version to use in Automation OpenAPI calls.|String|All|
|`automation_trustedCertificateCNs`|`tenant-manager-0.tenant-manager.prelude.svc.cluster.local`,`vcf-cluster-ca`|An array of trusted certificate common names that are validated and trusted. The internal Automation CAs are provided here by default.|Array|VCFA-9X-000373|
|`automation_approvedFeatureFlags`|`[]`|An array of approved feature flags by display name.|Array|VCFA-9X-000375|

## Running InSpec/CINC-auditor

### How to get an API token
A session token is needed to run an audit for VCF Automation to support the API queries used in the audit.

A session token can be retrieved in different ways but curl is shown in this example.
```
# Generate a base64 encoded string from the username:password text.
# Replace <base64credential> with the generated text and replace <vcfa_fqdn> with the VCF Automation FQDN.
curl -i -k -X POST -H 'Authorization: Basic <base64credential>' -H 'Accept: application/*;version=40.0' https://<vcfa_fqdn>/cloudapi/1.0.0/sessions/provider

# Alternatively the credentials to generate a session token can be provided as shown below.
# Replace <username:password> with the generated text and replace <vcfa_fqdn> with the VCF Automation FQDN.
curl -i -k -X POST -u "<username:password>" -H 'Accept: application/*;version=40.0' https://<vcfa_fqdn>/cloudapi/1.0.0/sessions/provider
```
Capture the token from the returned `x-vmware-vcloud-access-token` header and enter this in the inputs file used for the value of the `automation_sessionToken` input.

### Prepare inputs file
Provide the target environments inputs values in the inputs file to be used for the scan.

### Running the audit
The example commands below can be adapted to different environments and different paths as needed. 

**NOTE** If using CINC instead of InSpec, replace the `inspec` command with `cinc-auditor` for the best experience.  

Run the profile against a VCF Automation target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/automation --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/automation/inputs-example.yml
```

Run the profile against a VCF Automation target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI and JSON.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/automation --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/automation/inputs-example.yml --reporter=cli json:<path to report>.json
```

Run the profile against a VCF Automation target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI but only audit a specific control.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/automation --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/automation/inputs-example.yml --controls VCFA-9X-000104
```

Run the profile against a VCF Automation target, show progress, enable enhanced outcomes, provide inputs via an inputs file, specify a waiver file, and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/automation --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/automation/inputs-example.yml --waiver-file <path to>/waiver-example.yml
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
