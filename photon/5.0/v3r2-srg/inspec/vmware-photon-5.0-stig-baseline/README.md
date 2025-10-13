# vmware-photon-5.0-stig-baseline
Photon OS 5.0 STIG Readiness Guide Chef InSpec Profile  
Version: Version 3 Release 2 Date: 01 October 2025  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance.  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine with network access to the target. Tested with version 6.8.11. Chef/CINC Workstation can also be installed.
- SSH access to Photon instance.

## Supported Versions
- VCF 9.0.0.0 Photon 5 based appliances.

## Inputs
Inputs for an InSpec profile are sometimes needed to provide environment specific values in order for tests to run correctly. These can be provided by specifying an inputs file with your environments values.

An example inputs file is provided with this profile and can be found in the `inputs-example.yml` file. This file can be reused or copied and modified as needed.

Below is a list of inputs available for this profile that can be provided.  

|     Input Name    |       Default Value       | Description |     Type    |   STIG IDs  |
|-------------------|---------------------------|-------------|-------------|-------------|
|authprivlog        |/var/log/messages          |The expected log path for the authpriv log in the rsyslog config.|String|PHTN-50-000012|
|containerHost      |false                      |Used to indicate if system is a container host and running Kubernetes/Docker/etc for controls where this would make them N/A.|Boolean|PHTN-50-000231|
|useFaillockConf    |true                       |Used to indicate that `/etc/security/faillock.conf` is used to configure `pam_faillock.so`.|Boolean|PHTN-50-000004,PHTN-50-000108,PHTN-50-000193,,PHTN-50-000194,PHTN-50-000195,PHTN-50-000196|
|usePwqualityConf   |true                       |Used to indicate that `/etc/security/pwquality.conf` is used to configure `pam_pwquality.so`.|Boolean|PHTN-50-000035,PHTN-50-000036,PHTN-50-000037,,PHTN-50-000038,PHTN-50-000044,PHTN-50-000086,PHTN-50-000184,PHTN-50-000235,PHTN-50-000261,PHTN-50-000262,PHTN-50-000263,PHTN-50-000264|
|usePwhistoryConf   |true                       |Used to indicate that `/etc/security/pwhistory.conf` is used to configure `pam_pwhistory.so`.|Boolean|PHTN-50-000265|

## Running InSpec/CINC-auditor

### Prepare inputs file
Provide the target environments inputs values in the inputs file to be used for the scan.

### Running the audit
The example commands below can be adapted to different environments and different paths as needed. 

**NOTE** If using CINC instead of InSpec, replace the `inspec` command with `cinc-auditor` for the best experience.  

Run the profile against a Photon 5 target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-photon-5.0-stig-baseline --show-progress --enhanced-outcomes --input-file <path to>/vmware-photon-5.0-stig-baseline/inputs-example.yml
```

Run the profile against a Photon 5 target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI and JSON.
```
cinc-auditor exec <path to>/vmware-photon-5.0-stig-baseline --show-progress --enhanced-outcomes --input-file <path to>/vmware-photon-5.0-stig-baseline/inputs-example.yml --reporter=cli json:<path to report>.json
```

Run the profile against a Photon 5 target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI but only audit a specific control.
```
cinc-auditor exec <path to>/vmware-photon-5.0-stig-baseline --show-progress --enhanced-outcomes --input-file <path to>/vmware-photon-5.0-stig-baseline/inputs-example.yml --controls PHTN-50-000005
```

Run the profile against a Photon 5 target, show progress, enable enhanced outcomes, provide inputs via an inputs file, specify a waiver file, and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-photon-5.0-stig-baseline --show-progress --enhanced-outcomes --input-file <path to>/vmware-photon-5.0-stig-baseline/inputs-example.yml --waiver-file <path to>/waiver-example.yml
```

## Waivers
An example waiver file is provided for reference if waivers are required to be documented. More information about InSpec waivers can be found in the [InSpec Waiver Documentation](https://docs.chef.io/inspec/waivers/)  

## Reporting
InSpec supports various reporting formats out of the box including HTML, JSON, and jUNIT.  

There are also supplemental tools like [MITRE's SAF CLI](https://github.com/mitre/saf) that can be used to transform results to other formats like a STIG Checklist file.  

Results can also be imported into [MITRE's Heimdall](https://github.com/mitre/heimdall2) server for a more polished visual result.

## InSpec Vendoring
When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with `inspec vendor --overwrite`
