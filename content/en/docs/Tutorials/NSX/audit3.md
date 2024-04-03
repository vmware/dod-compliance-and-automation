---
title: "Audit NSX-T 3.x"
weight: 4
description: >
  Auditing NSX-T 3.x for STIG Compliance
---
## Overview
Auditing NSX-T 3.x for STIG compliance involves scanning the NSX Managers, DFW, and any gateways deployed.

To audit NSX-T using InSpec we utilize the local transport to connect via the REST API and query it's configuration.  

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vmware-nsxt-3.x-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline) profile downloaded.
* InSpec/Cinc Auditor 5.22.3
* SAF CLI 1.2.20
* STIG Viewer 2.17
* An NSX-T 3.x environment. 3.2.3 was used in these examples with 1 T0 Gateway configured with BGP to an upstream router and 1 T1 Gateway deployed.

## Auditing NSX-T
### Generate API Session Token
This profile uses Session-Based authentication to authenticate with NSX for auditing. A session token and cookie must be generated and provided an input for the profile. This can be generated in various ways via curl, tools like Postman, etc. For more information see the [NSX API Documentation](https://developer.vmware.com/apis/1248/nsx-t).

**Note:** If the user is a remote user, append "@domain" to the username, for example, "joe@example.com". The domain must match a domain for a configured VIDM identity source or a configured LDAP identity source.  

Curl example
```bash
curl -k -i -X POST -d 'j_username=admin&j_password=replacethis' https://10.43.173.83/api/session/create

# Example response
HTTP/1.1 200
Set-Cookie: JSESSIONID=6A0F43FCD07947BB21890CDA05DF26C0; Path=/; Secure; HttpOnly
X-XSRF-TOKEN: fe3d6167-09d5-4302-b6cd-be2e20947d58
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Type: application/json
Content-Length: 107
Date: Thu, 06 Jul 2023 17:15:07 GMT
Server: NSX

{"roles":[{"role":"superusers","permissions":["read-api","read-write-api","read-cli","read-write-cli"]}]}
```

### Update profile inputs
Included in the `vmware-nsxt-3.x-stig-baseline` is an example [inputs-nsxt-3.x.yml](https://github.com/vmware/dod-compliance-and-automation/blob/master/nsx/3.x/inspec/vmware-nsxt-3.x-stig-baseline/inputs-nsxt-3.x.yml) file with the following inputs relevant to NSX-T.

Update the inputs as shown below with values relevant to your environment.
```yaml
# General
# NSX Manager IP or FQDN
nsxManager: '10.43.173.83'
# Session token generated for access to NSX
sessionToken: 'fe3d6167-09d5-4302-b6cd-be2e20947d58'
# Session cookie id generated for access to NSX. Example 'JSESSIONID=2A165FCF851CA50FCD038DFC8E770038'
sessionCookieId: 'JSESSIONID=6A0F43FCD07947BB21890CDA05DF26C0'
# Manager
# Enter the environment specific syslog server vCenter should be forwarding logs to.
syslogServers:
  - 'loginsight.test.com'
  - 'loginsight2.test.com'
# Enter the environment specific time servers.
ntpServer1: 'time-a-g.nist.gov'
ntpServer2: 'time-b-g.nist.gov'
# Enter latest NSX version. Example '3.2.3.0'
nsxtVersion: '3.2.3.0'
# Enter an array of T0 Gateways that are approved to have multicast enabled.
t0multicastlist: []
# Enter an array of T0 Gateways interfaces that are approved to have multicast enabled.
t0mcinterfacelist: []
# Enter an array of T0 Gateways that are approved to have DHCP enabled.
t0dhcplist: []
# Enter an array of T1 Gateways that are approved to have DHCP enabled.
t1dhcplist: []
# Enter an array of T1 Gateways that are approved to have multicast enabled.
t1multicastlist: []
```

### Run the audit
In this example we will be scanning all NSX components, specifying an inputs file, and outputting a report to the CLI and to a JSON file.  
```bash
# Note this command is being ran from the root of the profile folder. Update paths as needed if running from a different location.
> inspec exec . --show-progress --input-file inputs-nsxt-3.x.yml --reporter=cli json:/mnt/c/Inspec/Reports/MyNSX3Report.json

# Shown below is the last part of the output at the CLI.
  ×  T1FW-3X-000036: The NSX-T Tier-1 Gateway Firewall must configure SpoofGuard to block outbound IP packets that contain illegitimate packet attributes. (6 failed)
     ✔  HTTP GET on https://10.43.173.83/api/v1/logical-switches status is expected to cmp == 200
     ✔  HTTP GET on https://10.43.173.83/policy/api/v1/search?query=( resource_type:SpoofGuardProfile AND unique_id:fad98876-d7ff-11e4-b9d6-1681e6b88ec1 ) status is expected to cmp == 200
     ×  JSON content address_binding_allowlist is expected to cmp == "true"

     expected: true
          got: false

     (compared using `cmp` matcher)

     ×  JSON content address_binding_whitelist is expected to cmp == "true"

     expected: true
          got: false

     (compared using `cmp` matcher)

     ✔  HTTP GET on https://10.43.173.83/policy/api/v1/search?query=( resource_type:SpoofGuardProfile AND unique_id:fad98876-d7ff-11e4-b9d6-1681e6b88ec1 ) status is expected to cmp == 200
     ×  JSON content address_binding_allowlist is expected to cmp == "true"

     expected: true
          got: false

     (compared using `cmp` matcher)

     ×  JSON content address_binding_whitelist is expected to cmp == "true"

     expected: true
          got: false

     (compared using `cmp` matcher)

     ✔  HTTP GET on https://10.43.173.83/policy/api/v1/search?query=( resource_type:SpoofGuardProfile AND unique_id:fad98876-d7ff-11e4-b9d6-1681e6b88ec1 ) status is expected to cmp == 200
     ×  JSON content address_binding_allowlist is expected to cmp == "true"

     expected: true
          got: false

     (compared using `cmp` matcher)

     ×  JSON content address_binding_whitelist is expected to cmp == "true"

     expected: true
          got: false

     (compared using `cmp` matcher)



Profile:   VMware NSX-T Tier 1 Gateway RTR STIG InSpec Profile (VMware NSX-T Tier 1 Gateway RTR STIG InSpec Profile)
Version:   1.1
Target:    local://
Target ID: 91850cb0-e902-5c20-9e21-05288aec4f93

  ↺  T1RT-3X-000016: The NSX-T Tier-1 Gateway must be configured to have all inactive interfaces removed. (1 skipped)
     ✔  HTTP GET on https://10.43.173.83/policy/api/v1/infra/tier-1s status is expected to cmp == 200
     ↺  This is a manual check. Review T1 interfaces and determine if any existing interfaces are orphaned and should be removed.
  ✔  T1RT-3X-000027: The NSX-T Tier-1 Gateway must be configured to have the DHCP service disabled if not in use.
     ✔  HTTP GET on https://10.43.173.83/policy/api/v1/infra/tier-1s status is expected to cmp == 200
     ✔  {"tier0_path"=>"/infra/tier-0s/Tier0Gateway1", "failover_mode"=>"NON_PREEMPTIVE", "enable_standby_relocation"=>false, "route_advertisement_types"=>["TIER1_CONNECTED", "TIER1_STATIC_ROUTES"], "route_advertisement_rules"=>[{"name"=>"Rule 1", "subnets"=>["192.168.1.0/24", "192.168.2.0/24"], "prefix_operator"=>"GE", "action"=>"PERMIT"}], "force_whitelisting"=>false, "default_rule_logging"=>false, "disable_firewall"=>false, "ipv6_profile_paths"=>["/infra/ipv6-ndra-profiles/default", "/infra/ipv6-dad-profiles/default"], "pool_allocation"=>"ROUTING", "advanced_config"=>{"traffic_back_to_source"=>false}, "resource_type"=>"Tier1", "id"=>"Tier1Gateway1", "display_name"=>"Tier1Gateway1", "description"=>"Tier1-1 created through automation", "path"=>"/infra/tier-1s/Tier1Gateway1", "relative_path"=>"Tier1Gateway1", "parent_path"=>"/infra", "unique_id"=>"74a2d444-07e6-49c9-bdb8-973c1ad81524", "realization_id"=>"74a2d444-07e6-49c9-bdb8-973c1ad81524", "marked_for_delete"=>false, "overridden"=>false, "_create_time"=>1688661706117, "_create_user"=>"admin", "_last_modified_time"=>1688661706117, "_last_modified_user"=>"admin", "_system_owned"=>false, "_protection"=>"NOT_PROTECTED", "_revision"=>0} ["dhcp_config_paths"] is expected to equal nil
  ↺  T1RT-3X-000034: The NSX-T Tier-1 Gateway must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks. (1 skipped)
     ✔  HTTP GET on https://10.43.173.83/policy/api/v1/infra/tier-1s status is expected to cmp == 200
     ↺  This is a manual check. Review that QoS policies support traffic priorities specified by the Combatant Commands/Services/Agencies needed to ensure sufficient capacity for mission-critical traffic.
  ✔  T1RT-3X-000084: The NSX-T Tier-1 Gateway must be configured to have multicast disabled if not in use.
     ✔  HTTP GET on https://10.43.173.83/policy/api/v1/infra/tier-1s status is expected to cmp == 200
     ✔  HTTP GET on https://10.43.173.83/policy/api/v1/infra/tier-1s/Tier1Gateway1/locale-services/Tier1LocalServices-1/multicast status is expected to cmp == 404


Profile Summary: 24 successful controls, 35 control failures, 12 controls skipped
Test Summary: 176 successful, 60 failures, 15 skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

```powershell
# Converting the scan results from the prior section to CKL
saf convert hdf2ckl -i C:\inspec\Reports\MyNSX3Report.json -o C:\inspec\Reports\MyNSX3Report.ckl --hostname 10.43.173.83 --fqdn 10.43.173.83 --ip 10.43.173.83 --mac 00:00:00:00:00:00
```

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  

![alt text](/images/nsx_audit3_ckl_screenshot.png)