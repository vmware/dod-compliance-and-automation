# vmware-cloud-foundation-operations-logs-stig-baseline
VMware Cloud Foundation Operations for Logs 9.0 STIG Readiness Guide Chef InSpec Profile  
Updated: 2025-06-17  
STIG Release: Y25M06  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance.  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine with network access to the target. Tested with version 6.8.24. Chef/CINC Workstation can also be installed and used.
- Running against a supported product version for this profile.
- SSH access to target system
- The `vmware-cloud-foundation-operations-logs-stig-baseline` profile downloaded to a local folder on either Windows or Linux.
- The `vmware-photon-5.0-stig-baseline` profile downloaded to a local folder on either Windows or Linux. This must be in the same root folder as the `vmware-cloud-foundation-operations-logs-stig-baseline` profile.

## Supported Versions
- VCF 9.0.0.0  

## Inputs
Inputs for an InSpec profile are sometimes needed to provide environment specific values in order for tests to run correctly. These can be provided by specifying an inputs file with the target environments values.  

An example inputs file is provided with in the parent folder and can be found in the `inputs-example.yml` file. This file can be reused, copied, or modified as needed. 

Below is a list of inputs available for this profile that can be provided.  

|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|

No environment specific inputs are needed at this time for this profile.  

## Running InSpec/CINC-auditor

### Prepare inputs file
Provide the target environments inputs values in the inputs file to be used for the scan.

### Running the audit
The example commands below can be adapted to different environments and different paths as needed. 

**NOTE** If using CINC instead of InSpec, replace the `inspec` command with `cinc-auditor` for the best experience.  

Run the profile against a VCF Operations Fleet Management target, show progress, enable enhanced outcomes.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-operations-logs-stig-baseline --show-progress --enhanced-outcomes
```

Run the profile against a VCF Operations Fleet Management target, show progress, enable enhanced outcomes, and output results to the CLI and JSON.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-operations-logs-stig-baseline --show-progress --enhanced-outcomes --reporter=cli json:<path to report>.json
```

Run the profile against a VCF Operations Fleet Management target, show progress, enable enhanced outcomes, and output results to the CLI but only audit a specific control.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-operations-logs-stig-baseline --show-progress --enhanced-outcomes --controls PHTN-50-000005
```

Run the profile against a VCF Operations Fleet Management target, show progress, enable enhanced outcomes, specify a waiver file, and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-operations-logs-stig-baseline --show-progress --enhanced-outcomes --waiver-file <path to>/waiver-example.yml
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
