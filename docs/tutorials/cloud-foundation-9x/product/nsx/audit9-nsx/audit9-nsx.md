# Audit NSX 9.0.0.0

## Overview
This tutorial covers auditing NSX product rules in VCF deployments.  

The example commands below are specific to the product version and the supported STIG content for the version being run. Select the appropriate tab for the target version.

### Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* InSpec/Cinc Auditor 6.8.24
* SAF CLI 1.4.20
* STIG Viewer 2.17
* A VCF 9.0.0.0 or newer environment.

### Assumptions
* Commands are being run from a Linux machine. Windows will also work but paths and commands may need to be adjusted from the examples.
* The [DOD Compliance and Automation](https://github.com/vmware/dod-compliance-and-automation) repository has been downloaded and extracted to `/usr/share/stigs`.
* CINC Auditor is used in lieu of InSpec. If InSpec is used replace `cinc-auditor` with `inspec` when running commands.

## Auditing NSX
Auditing NSX for STIG compliance is done via the API.

### Generate an API Session Token
This profile uses Session-Based authentication to authenticate with NSX for auditing. A session token can be retrieved through the `/api/session/create` API call. 

A token can be generated via curl or other REST client. A curl example is shown below.

For more information see the [NSX API Documentation](https://developer.vmware.com/apis/1733/).

**Note:** If the user is a remote user, append "@domain" to the username, for example, "joe@example.com". The domain must match a domain for a configured identity source or a configured LDAP identity source.  

Curl example:

```
# Replace myuser, mypassword, and update the url
curl -k -i -X POST -d 'j_username=myuser&j_password=mypassword' https://nsxmgr.rainpole.local/api/session/create

# Example response
HTTP/1.1 200
Set-Cookie: JSESSIONID=0FB1F72478DDE578AB7E3473F54BCF50; Path=/; Secure; HttpOnly
X-XSRF-TOKEN: ae5ee920-bca1-4ba3-ac1f-385e76f2c66a
```

### Update InSpec input values
Inputs for an InSpec profile are sometimes needed to provide environment specific values in order for tests to run correctly. These can be provided by specifying an inputs file with the relevant environmental values.

An example inputs file is provided with this profile and can be found in the `inputs-example.yml` file. This file can be reused or copied and modified as needed.

Below is a list of inputs available for this profile that can be provided.  

|        Input Name         |       Default Value       | Description                     |     Type    |   STIG IDs  |
|---------------------------|---------------------------|---------------------------------|-------------|-------------|
|nsx_managerAddress         |`blank`                    |Target NSX Manager IP or FQDN.   |String|All|
|nsx_sessionToken           |`blank`                    |Session token generated for access to NSX.|Boolean|All|
|nsx_sessionCookieId        |`blank`                    |Session cookie id generated for access to NSX. Example 'JSESSIONID=2A165FCF851CA50FCD038DFC8E770038'|String|All|
|nsx_authorizedPermissions  |See inputs example file    |A list of authorized users and their roles to validate assigned permissions in NSX. The default local users and their roles are provided as an example. This currently only validates roles assigned to all of NSX and not to Projects or other scopes.|Hash|VCFN-9X-000010|
|nsx_allowedProtocols       |`TLSv1.2` `TLSv1.3`        |Allowed TLS protocols            |Array|VCFN-9X-000037|
|nsx_allowedCiphers         |`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` `TLS_RSA_WITH_AES_128_GCM_SHA256` `TLS_RSA_WITH_AES_256_GCM_SHA384` `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` `TLS_AES_128_GCM_SHA256` `TLS_AES_128_GCM_SHA384`|Allowed TLS ciphers|Array|VCFN-9X-000075|
|nsx_syslogServers          |`[]`                       |A list of Syslog servers to which the system should forward logs.|Array|VCFN-9X-000085|
|nsx_ntpServers             |`[]`                       |A list of NTP servers with which the system should sync.|Array|VCFN-9X-000111|
|nsx_t0multicastlist        |`[]`                       |A list of T0 Gateways that are approved to have multicast enabled.|Array|VCFR-9X-000013,VCFR-9X-000110|
|nsx_t0mcinterfacelist      |`[]`                       |A list of T0 Gateways interfaces that are approved to have multicast enabled.|Array|VCFR-9X-000013|
|nsx_t0dhcplist             |`[]`                       |A list of T0 Gateways that are approved to have DHCP enabled.|Array|VCFR-9X-000027|
|nsx_t1dhcplist             |`[]`                       |A list of T1 Gateways that are approved to have DHCP enabled.|Array|VCFR-9X-000113|
|nsx_t1multicastlist        |`[]`                       |A list of T1 Gateways that are approved to have multicast enabled.|Array|VCFR-9X-000115|

#### Updating the inputs file
Update the example inputs file or create one and provide the environment specific values for the audit.  

```
# Navigate to the NSX InSpec profile
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/nsx/

# Edit the inputs-example.yml file
vi inputs-example.yml

# Update the values as needed
nsx_managerAddress: 'nsxmgr.rainpole.local'
nsx_sessionToken: 'ae5ee920-bca1-4ba3-ac1f-385e76f2c66a'
nsx_sessionCookieId: 'JSESSIONID=0FB1F72478DDE578AB7E3473F54BCF50'
# Provide a list of authorized users and their roles to validate assigned permissions in NSX. The default local users and their roles are provided as an example. This currently only validates roles assigned to all of NSX and not to Projects or other scopes.
nsx_authorizedPermissions:
  admin:
    role: 'Enterprise Admin'
  audit:
    role: 'Auditor'
  guestuser1:
    role: 'Auditor'
  guestuser2:
    role: 'Auditor'
# Enter the environment specific syslog server NSX should be forwarding logs to.
nsx_syslogServers:
  - 'loginsight.test.com'
# Enter the environment specific time servers.
nsx_ntpServers:
  - 'time-a-g.nist.gov'
  - 'time-b-g.nist.gov'
# Enter an array of T0 Gateways that are approved to have multicast enabled.
nsx_t0multicastlist: []
# Enter an array of T0 Gateways interfaces that are approved to have multicast enabled.
nsx_t0mcinterfacelist: []
# Enter an array of T0 Gateways that are approved to have DHCP enabled.
nsx_t0dhcplist: []
# Enter an array of T1 Gateways that are approved to have DHCP enabled.
nsx_t1dhcplist: []
# Enter an array of T1 Gateways that are approved to have multicast enabled.
nsx_t1multicastlist: []
```

### Run the audit
In this example NSX will be scanned and reporting will output to the CLI and to a JSON file.  

```
# Navigate to the NSX InSpec profile
cd /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/nsx/

# Run the audit
cinc-auditor exec . --show-progress --enhanced-outcomes --input-file inputs-example.yml --reporter cli json:/tmp/reports/VCF_9_NSX_Report.json

# Shown below is the last part of the output at the CLI.
Profile Summary: 62 successful controls, 10 control failures, 4 controls not reviewed, 2 controls not applicable, 0 controls have error
Test Summary: 121 successful, 24 failures, 6 skipped

```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

### Update the target details in the metadata file
First update the target hostname, hostip, hostmac, and hostfqdn fields in the `saf_cli_hdf2ckl_metadata.json` metadata file

```
# Update the saf_cli_hdf2ckl_metadata.json file
vi /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/saf_cli_hdf2ckl_metadata.json

"hostname": "nsxmgr.rainpole.local",
"hostip": "10.1.1.30",
"hostmac": "00:00:00:00:00:00",
"hostfqdn": "nsxmgr.rainpole.local",
```

### Run SAF CLI to create the CKL file
The following command will convert the json result from the InSpec audit into a STIG Checklist file and ensure the correct metadata is inserted so that it displays correctly in STIG Viewer.  

```
# Convert the InSpec report to a STIG Checklist
saf convert hdf2ckl -i /tmp/reports/VCF_9_NSX_Report.json -o /tmp/reports/VCF_9_NSX_Report.ckl -m /usr/share/stigs/vcf/9.x/Y25M06-srg/inspec/vmware-cloud-foundation-stig-baseline/saf_cli_hdf2ckl_metadata.json
```

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  
![STIG Viewer Checklist](../../../../images/nsx_audit9_ckl_screenshot.png)

## Manually audit rules
The following rules require manual auditing and are not automated.  

| STIG ID              | Title                                                                                                                                   |
|----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `VCFR-9X-000016`     |The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to have all inactive interfaces removed.                               |
| `VCFR-9X-000055`     |The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to use a unique password for each autonomous system (AS) with which it peers.|
| `VCFR-9X-000091`     |The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to use its loopback address as the source address for iBGP peering sessions.|
| `VCFR-9X-000112`     |The VMware Cloud Foundation NSX Tier-1 Gateway must be configured to have all inactive interfaces removed.                               |

## Next
If needed proceed to the remediation tutorial for NSX [here](/docs/tutorials/cloud-foundation-9.x/product/nsx/remediate9-nsx/).
