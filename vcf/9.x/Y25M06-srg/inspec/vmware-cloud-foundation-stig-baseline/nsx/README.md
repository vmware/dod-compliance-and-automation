# vmware-cloud-foundation-nsx-stig-baseline
VMware Cloud Foundation NSX 9.0 STIG Readiness Guide Chef InSpec Profile  
Updated: 2025-06-17  
STIG Release: Y25M06  
STIG Type: STIG Readiness Guide  
Maintainers: Broadcom  

## Overview
This is a compliance auditing profile that is based on Chef InSpec/CINC Auditor to perform an automated check for STIG compliance.  

## Requirements
- [Chef InSpec](https://downloads.chef.io/tools/inspec) or [CINC Auditor](https://cinc.sh/start/auditor/) installed on a machine with network access to the target. Tested with version 6.8.24. Chef/CINC Workstation can also be installed and used.
- Running against a supported product version for this profile.
- Administrative or audit access to the target
- An API token and session id cookie is needed for the tests to make API calls. Specify it on the command line or in the inputs file.  See https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/ for more details.
- The `vmware-cloud-foundation-stig-baseline` profile downloaded to a local folder on either Windows or Linux.

## Supported Versions
- VCF 9.0.0.0   

## Inputs
Inputs for an InSpec profile are sometimes needed to provide environment specific values in order for tests to run correctly. These can be provided by specifying an inputs file with the target environments values.  

An example inputs file is provided with in the parent folder and can be found in the `inputs-example.yml` file. This file can be reused, copied, or modified as needed.  

Below is a list of inputs available for this profile that can be provided.  

|     Input Name       |       Default Value       | Description |     Type    |   STIG IDs  |
|----------------------|---------------------------|-------------|-------------|-------------|
|`nsx_managerAddress`  |`blank`                    |Target NSX Manager IP or FQDN.|String|All|
|`nsx_sessionToken`    |`blank`                    |Session token generated for access to NSX.|Boolean|All|
|`nsx_sessionCookieId` |`blank`                    |Session cookie id generated for access to NSX. Example 'JSESSIONID=2A165FCF851CA50FCD038DFC8E770038'|String|All|
|`nsx_authorizedPermissions`|See inputs example file    |A list of authorized users and their roles to validate assigned permissions in NSX. The default local users and their roles are provided as an example. This currently only validates roles assigned to all of NSX and not to Projects or other scopes.|Hash|VCFN-9X-000010|
|`nsx_allowedProtocols`|`TLSv1.2` `TLSv1.3`        |Allowed TLS protocols|Array|VCFN-9X-000037|
|`nsx_allowedCiphers`  |`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` `TLS_RSA_WITH_AES_128_GCM_SHA256` `TLS_RSA_WITH_AES_256_GCM_SHA384` `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` `TLS_AES_128_GCM_SHA256` `TLS_AES_128_GCM_SHA384`|Allowed TLS ciphers|Array|VCFN-9X-000075|
|`nsx_syslogServers`   |`[]`                       |A list of Syslog servers with which the system should forward logs.|Array|VCFN-9X-000085|
|`nsx_ntpServers`      |`[]`                       |A list of NTP servers with which the system should sync.|Array|VCFN-9X-000111|
|`nsx_t0multicastlist` |`[]`                       |A list of T0 Gateways that are approved to have multicast enabled.|Array|VCFR-9X-000013,VCFR-9X-000110|
|`nsx_t0mcinterfacelist`|`[]`                       |A list of T0 Gateways interfaces that are approved to have multicast enabled.|Array|VCFR-9X-000013|
|`nsx_t0dhcplist`      |`[]`                       |A list of T0 Gateways that are approved to have DHCP enabled.|Array|VCFR-9X-000027|
|`nsx_t1dhcplist`      |`[]`                       |A list of T1 Gateways that are approved to have DHCP enabled.|Array|VCFR-9X-000113|
|`nsx_t1multicastlist` |`[]`                       |A list of T1 Gateways that are approved to have multicast enabled.|Array|VCFR-9X-000115|

### How to get an API token
A session token and cookie id is needed to run an audit for NSX to support the API queries used in the audit.  

A session token can be retrieved through the `/api/session/create` API call. 

A token can be generated via curl or other REST client. A curl example is shown below.

```
curl -k -i -X POST -d 'j_username=myuser&j_password=mypassword' https://nsx-mgmt-1.vrack.vsphere.local/api/session/create

# Example response
HTTP/1.1 200
Set-Cookie: JSESSIONID=0FB1F72478DDE578AB7E3473F54BCF50; Path=/; Secure; HttpOnly
X-XSRF-TOKEN: ae5ee920-bca1-4ba3-ac1f-385e76f2c66a
```
Capture the x-xsrf-token and jsessionid from the returned response and enter this in the inputs file used for the value of the `nsx_sessionToken` and `nsx_sessionCookieId` inputs.

For Example:
```
# NSX Manager IP or FQDN
nsx_managerAddress: 'nsx-mgmt-1.vrack.vsphere.local'
# Session token generated for access to NSX. Example ead781b8-0e0c-456f-a04a-584e9ae2e45a
nsx_sessionToken: 'ae5ee920-bca1-4ba3-ac1f-385e76f2c66a'
# Session cookie id generated for access to NSX. Example 'JSESSIONID=2A165FCF851CA50FCD038DFC8E770038'
nsx_sessionCookieId: 'JSESSIONID=0FB1F72478DDE578AB7E3473F54BCF50'
```

### Prepare inputs file
Provide the target environments inputs values in the inputs file to be used for the scan.

### Running the audit
The example commands below can be adapted to different environments and different paths as needed. 

**NOTE** If using CINC instead of InSpec, replace the `inspec` command with `cinc-auditor` for the best experience.  

Run the profile against a NSX Manager target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/nsx --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/nsx/inputs-example.yml
```

Run the profile against a NSX Manager target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI and JSON.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/nsx --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/nsx/inputs-example.yml --reporter=cli json:<path to report>.json
```

Run the profile against a NSX Manager target, show progress, enable enhanced outcomes, provide inputs via an inputs file and output results to the CLI but only audit a specific control.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/nsx --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/nsx/inputs-example.yml --controls VCFN-9X-000007
```

Run the profile against a NSX Manager target, show progress, enable enhanced outcomes, provide inputs via an inputs file, specify a waiver file, and output results to the CLI.
```
cinc-auditor exec <path to>/vmware-cloud-foundation-stig-baseline/nsx --show-progress --enhanced-outcomes --input-file <path to>/vmware-cloud-foundation-stig-baseline/nsx/inputs-example.yml --waiver-file <path to>/waiver-example.yml
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
