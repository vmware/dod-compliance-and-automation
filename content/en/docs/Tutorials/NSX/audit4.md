---
title: "Audit NSX 4.x"
weight: 3
description: >
  Auditing NSX 4.x for STIG Compliance
---
## Overview
Auditing NSX 4.x for STIG compliance involves scanning the NSX Managers and any gateways deployed.

To audit NSX using InSpec we utilize the local transport to connect via the REST API and query it's configuration.  

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vmware-nsx-4.x-stig-baseline](https://github.com/vmware/dod-compliance-and-automation/tree/master/nsx/4.x/inspec/vmware-nsx-4.x-stig-baseline) profile downloaded.
* InSpec/Cinc Auditor 5.22.3
* SAF CLI 1.2.20
* STIG Viewer 2.17
* An NSX 4.x environment. 4.1.0.2 was used in these examples with 1 T0 Gateway configured with BGP to an upstream router and 1 T1 Gateway deployed.

## Auditing NSX-T
### Generate API Session Token
This profile uses Session-Based authentication to authenticate with NSX for auditing. A session token and cookie must be generated and provided an input for the profile. This can be generated in various ways via curl, tools like Postman, etc. For more information see the [NSX API Documentation](https://developer.vmware.com/apis/1583/nsx-t).

**Note:** If the user is a remote user, append "@domain" to the username, for example, "joe@example.com". The domain must match a domain for a configured VIDM identity source or a configured LDAP identity source.  

Curl example
```bash
curl -k -i -X POST -d 'j_username=admin&j_password=C3.UwJ7TTK1P' https://10.215.77.149/api/session/create

# Example response
HTTP/1.1 200 OK
set-cookie: JSESSIONID=A6903A10F3AE7EB328F12EAF796053F5; Path=/; Secure; HttpOnly; SameSite=Lax
x-xsrf-token: ead781b8-0e0c-456f-a04a-584e9ae2e45a
cache-control: no-cache, no-store, max-age=0, must-revalidate
pragma: no-cache
expires: 0
x-xss-protection: 1; mode=block
x-frame-options: SAMEORIGIN
x-content-type-options: nosniff
content-type: application/json
content-length: 107
date: Thu, 29 Jun 2023 21:39:58 GMT
strict-transport-security: max-age=31536000; includeSubDomains
content-security-policy: frame-src 'self' blob:; frame-ancestors 'self'
server: envoy

{"roles":[{"role":"superusers","permissions":["read-api","read-write-api","read-cli","read-write-cli"]}]}
```

### Update profile inputs
Included in the `vmware-nsx-4.x-stig-baseline` is an example [inputs-nsx-4.x-example.yml](https://github.com/vmware/dod-compliance-and-automation/blob/master/nsx/4.x/inspec/vmware-nsx-4.x-stig-baseline/inputs-nsx-4.x-example.yml) file with the following inputs relevant to NSX.

Update the inputs as shown below with values relevant to your environment.
```yaml
# General
# NSX Manager IP or FQDN
nsxManager: '10.215.77.149'
# Session token generated for access to NSX
sessionToken: 'ead781b8-0e0c-456f-a04a-584e9ae2e45a'
# Session cookie id generated for access to NSX. Example 'JSESSIONID=2A165FCF851CA50FCD038DFC8E770038'
sessionCookieId: 'JSESSIONID=A6903A10F3AE7EB328F12EAF796053F5'
# Manager
# Enter the environment specific syslog server vCenter should be forwarding logs to.
syslogServers:
  - 'loginsight.test.com'
# Enter the environment specific time servers.
ntpServer1: 'time-a-g.nist.gov'
ntpServer2: 'time-b-g.nist.gov'
# Enter latest NSX version. Example '4.1.0.2'
nsxtVersion: '4.1.0.2'
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
> inspec exec . --show-progress --input-file inputs-nsx-4.x-example.yml --reporter=cli json:/mnt/c/Inspec/Reports/MyNSXReport.json

# Shown below is the last part of the output at the CLI.
  ×  NT1F-4X-000020: The NSX Tier-1 Gateway Firewall must be configured to send traffic log entries to a central audit server. (1 failed)
     ✔  HTTP GET on https://10.215.77.149/policy/api/v1/search?query=( resource_type:TransportNode AND node_deployment_info.resource_type:EdgeNode ) status is expected to cmp == 200
     ✔  HTTP GET on https://10.215.77.149/api/v1/transport-nodes/a40c4ea4-16a1-11ee-8640-000c296f3e4c/node/services/syslog/exporters status is expected to cmp == 200
     ×  No syslog servers are configured on Edge Node: rlakey-svc.nsxedge-ob-21981742-1-stigtest is expected not to cmp == []

     expected: []
          got: []

     (compared using `cmp` matcher)

  ↺  NT1F-4X-000027: The NSX Tier-1 Gateway Firewall must be configured to inspect traffic at the application layer. (1 skipped)
     ✔  HTTP GET on https://10.215.77.149/policy/api/v1/infra/tier-1s status is expected to cmp == 200
     ↺  This check is a manual or policy based check and must be reviewed manually.


Profile:   VMware NSX 4.x Tier-1 Gateway Router STIG InSpec Profile (VMware NSX 4.x Tier-1 Gateway Router STIG InSpec Profile)
Version:   1.1
Target:    local://
Target ID: e45dd517-9256-59e3-8503-3351c863444c

  ↺  NT1R-4X-000016: The NSX Tier-1 Gateway must be configured to have all inactive interfaces removed. (1 skipped)
     ✔  HTTP GET on https://10.215.77.149/policy/api/v1/infra/tier-1s status is expected to cmp == 200
     ↺  This is a manual check. Review T1 interfaces and determine if any existing interfaces are orphaned and should be removed.
  ✔  NT1R-4X-000027: The NSX Tier-1 Gateway must be configured to have the DHCP service disabled if not in use.
     ✔  HTTP GET on https://10.215.77.149/policy/api/v1/infra/tier-1s status is expected to cmp == 200
     ✔  {"tier0_path"=>"/infra/tier-0s/Tier0Gateway1", "failover_mode"=>"NON_PREEMPTIVE", "enable_standby_relocation"=>false, "route_advertisement_types"=>["TIER1_CONNECTED", "TIER1_STATIC_ROUTES"], "route_advertisement_rules"=>[{"name"=>"Rule 1", "subnets"=>["192.168.1.0/24", "192.168.2.0/24"], "prefix_operator"=>"GE", "action"=>"PERMIT"}], "force_whitelisting"=>false, "default_rule_logging"=>false, "disable_firewall"=>false, "ipv6_profile_paths"=>["/infra/ipv6-ndra-profiles/default", "/infra/ipv6-dad-profiles/default"], "pool_allocation"=>"ROUTING", "advanced_config"=>{"traffic_back_to_source"=>false, "centralized_mode_enabled"=>false}, "resource_type"=>"Tier1", "id"=>"Tier1Gateway1", "display_name"=>"Tier1Gateway1", "description"=>"Tier1-1 created through automation", "path"=>"/infra/tier-1s/Tier1Gateway1", "relative_path"=>"Tier1Gateway1", "parent_path"=>"/infra", "remote_path"=>"", "unique_id"=>"4f4dd7f0-30d7-4dff-8e9b-14524d6284a1", "realization_id"=>"4f4dd7f0-30d7-4dff-8e9b-14524d6284a1", "owner_id"=>"f1a08ebb-158a-4bed-908d-14cd342e4f9a", "marked_for_delete"=>false, "overridden"=>false, "_create_time"=>1688059851013, "_create_user"=>"admin", "_last_modified_time"=>1688059851013, "_last_modified_user"=>"admin", "_system_owned"=>false, "_protection"=>"NOT_PROTECTED", "_revision"=>0} ["dhcp_config_paths"] is expected to equal nil
  ↺  NT1R-4X-000102: The NSX Tier-1 Gateway must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments. (1 skipped)
     ✔  HTTP GET on https://10.215.77.149/policy/api/v1/infra/global-config status is expected to cmp == 200
     ↺  IPv6 Forwarding is not enabled. This is Not Applicable.
  ✔  NT1R-4X-000107: The NSX Tier-1 Gateway must be configured to have multicast disabled if not in use.
     ✔  HTTP GET on https://10.215.77.149/policy/api/v1/infra/tier-1s status is expected to cmp == 200
     ✔  HTTP GET on https://10.215.77.149/policy/api/v1/infra/tier-1s/Tier1Gateway1/locale-services/Tier1LocalServices-1/multicast status is expected to cmp == 404


Profile Summary: 21 successful controls, 30 control failures, 10 controls skipped
Test Summary: 162 successful, 57 failures, 12 skipped
```

## Convert the results to CKL
If a STIG Viewer CKL file is needed then the results from the scans can be converted to CKL with the [SAF CLI](/docs/automation-tools/safcli/).

```powershell
# Converting the scan results from the prior section to CKL
saf convert hdf2ckl -i C:\inspec\Reports\MyNSXReport.json -o C:\inspec\Reports\MyNSXReport.ckl --hostname 10.215.77.149 --fqdn 10.215.77.149 --ip 10.215.77.149 --mac 00:00:00:00:00:00
```

Opening the CKL file in STIG Viewer will look like the screenshot below. Note the InSpec results are included in the `Finding Details` pane.  

![alt text](/images/nsx_audit4_ckl_screenshot.png)