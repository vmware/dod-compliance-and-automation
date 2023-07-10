---
title: "Remediate NSX 4.x"
weight: 4
description: >
  Remediating NSX 4.x for STIG Compliance
---
## Overview
Remediating NSX 4.x for STIG compliance involves configuring the NSX Managers, DFW, and any gateways deployed.  

To remediate NSX, Ansible is the automation tool used to interact with the NSX REST API.   

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vmware-nsx-4.x-stig-ansible-hardening](https://github.com/vmware/dod-compliance-and-automation/tree/master/nsx/4.x/ansible/vmware-nsx-4.x-stig-ansible-hardening) playbook downloaded.
* Ansible 2.14.4
* Install [JMESPath](https://pypi.org/project/jmespath/) for community.general.json_query collection.
* An NSX 4.x environment. 4.1 was used in this example.
* An account with sufficient privileges to configure NSX.

## Important Considerations
<div class="-text-red pt-3 display-4">Please read carefully before proceding!</div>  

Some NSX STIG controls can be very impactful to your environment if care is not taken during implementation especially in a brownfield scenario. For example, changing the default DFW rule to deny traffic without first creating rules to allow authorized traffic.  

Below is a table of controls selected for consideration but all controls should be examined for impact before implementing.  

These can be turned on/off by with a variable that must be set to true as a condition for these tasks to run. See [Update vars file](#update-vars-file) for more details.

| STIG ID | Title | Notes |
|---------|-------|-------|
|NDFW-4X-000015|The NSX Distributed Firewall must limit the effects of packet flooding types of denial-of-service (DoS) attacks.||
|NDFW-4X-000016|The NSX Distributed Firewall must deny network communications traffic by default and allow network communications traffic by exception.|Ensure DFW rules are created to allow authorized traffic.|
|NDFW-4X-000029|The NSX Distributed Firewall must configure SpoofGuard to restrict it from accepting outbound packets that contain an illegitimate address in the source address.|Develop an operational plan to manage Spoofguard and identity workloads multiple IPs, etc, that may have issues.|
|NDFW-4X-000034|The NSX Distributed Firewall must configure an IP Discovery profile to disable trust on every use methods.|Develop an operational plan to manage Spoofguard and identity workloads multiple IPs, etc, that may have issues.|
|NT0F-4X-000015|The NSX Tier-0 Gateway Firewall must manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks.||
|NT0F-4X-000016|The NSX Tier-0 Gateway Firewall must deny network communications traffic by default and allow network communications traffic by exception.|Ensure gateway firewall rules are created to allow authorized traffic.|
|NT0R-4X-000013|The NSX Tier-0 Gateway must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.|Ensure any gateways that are authorized to enable multicast are listed in the vars file.|
|NT0R-4X-000027|The NSX Tier-0 Gateway must be configured to have the DHCP service disabled if not in use.|Ensure any gateways that are authorized to enable DHCP are listed in the vars file.|
|NT0R-4X-000107|The NSX Tier-0 Gateway must be configured to have multicast disabled if not in use.|Ensure any gateways that are authorized to enable multicast are listed in the vars file.|
|NT1F-4X-000015|The NSX Tier-1 Gateway Firewall must manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks.||
|NT1F-4X-000016|The NSX Tier-1 Gateway Firewall must deny network communications traffic by default and allow network communications traffic by exception.|Ensure gateway firewall rules are created to allow authorized traffic.|
|NT1R-4X-000027|The NSX Tier-1 Gateway must be configured to have the DHCP service disabled if not in use.|Ensure any gateways that are authorized to enable DHCP are listed in the vars file.|
|NT1R-4X-000107|The NSX Tier-1 Gateway must be configured to have multicast disabled if not in use.|Ensure any gateways that are authorized to enable multicast are listed in the vars file.|

Also not all controls are covered by the Ansible playbook and may require manual remediation.  

## Remediating NSX
To remediate NSX we have provided an [Ansible playbook](https://github.com/vmware/dod-compliance-and-automation/tree/master/nsx/4.x/ansible/vmware-nsx-4.x-stig-ansible-hardening) that will target an NSX Manager over the REST API and configure any non-compliant controls.  

Since Ansible can only be ran from Linux based systems, the examples below are being ran on an Ubuntu 22.04 WSL2 instance on Windows 11 for reference.  

### Generate API Session Token
This playbook uses Session-Based authentication to authenticate with NSX for remediation. A session token and cookie must be generated and provided an input for the profile. This can be generated in various ways via curl, tools like Postman, etc. For more information see the [NSX API Documentation](https://developer.vmware.com/apis/1583/nsx-t).

**Note:** If the user is a remote user, append "@domain" to the username, for example, "joe@example.com". The domain must match a domain for a configured VIDM identity source or a configured LDAP identity source.  

Curl example
```bash
curl -k -i -X POST -d 'j_username=admin&j_password=replacethis' https://10.180.98.230/api/session/create

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

### Update vars file
In order to run the playbook, environment specific values need to be provided. An example vars file `vars-nsx-4x-example.yml` is provided and values need to be updated for the `var_nsx_manager`, `var_jsession_id`, `var_session_token`, `var_ntp_server1`, `var_ntp_server2` variables at a minimum.  

```yaml
# Example vars file
# Connection information
var_nsx_manager: '10.180.98.230'
var_jsession_id: 'JSESSIONID=BDE1B5A54690B453F8968293D3C8A1E4'
var_session_token: '1d140509-ee7c-4cbf-9c22-9efdef982631'

# Manager
var_ntp_server1: 'time-a-g.nist.gov'
var_ntp_server2: 'time-b-g.nist.gov'

# DFW
# NDFW-4X-000004
run_dfw_enable_rule_logging: true
# NDFW-4X-000015
run_dfw_flood_protection: true
# NDFW-4X-000016
run_dfw_default_rule_action: false
var_dfw_default_rule_action: 'DROP'
# NDFW-4X-000029
run_dfw_spoofguard_profile: true
# NDFW-4X-000034
run_dfw_ip_discovery_profile: false

# T0 Firewall
# NT0F-4X-000016
run_t0fw_default_rule_action: false
var_t0fw_default_rule_action: 'DROP'

# T0 Router
# NT0R-4X-000013
run_t0rtr_disable_pim_on_interfaces: false
# array of t0 interface ids that should have PIM enabled
var_t0rtr_gateway_interfaces_with_multicast_enabled:
  - Tier0Interface1
# NT0R-4X-000027
run_t0rtr_disable_dhcp: false
# array of t0 ids that should have dhcp enabled
var_t0rtr_gateways_with_dhcp_enabled: []
# NT0R-4X-000107
run_t0rtr_disable_multicast: true
# array of t0 ids that should have multicast enabled
var_t0rtr_gateways_with_multicast_enabled:
  - Tier0Gateway1

# T1 Firewall
# NT1F-4X-000016
run_t1fw_default_rule_action: true
var_t1fw_default_rule_action: 'DROP'

# T1 Router
# NT1R-4X-000027
run_t1rtr_disable_dhcp: true
# array of t1 ids that should have dhcp enabled
var_t1rtr_gateways_with_dhcp_enabled: []
# NT1R-4X-000107
run_t1rtr_disable_multicast: true
# array of t1 ids that should have multicast enabled
var_t1rtr_gateways_with_multicast_enabled:
  - Tier1Gateway1
```

### Running the playbook
To run all of the NSX controls, follow the example below.
```bash
# The -k parameter will prompt for password and we are using extra-vars to specify a variable file for the playbook to use. Command assumes it is being ran from the playbook folder.
> ansible-playbook playbook.yml -v --extra-vars @vars-nsxt-3.x-example.yml

# Output example
PLAY [NSX 4.x Remediation Automation] ***************************************************************************************************************************************************************************************

TASK [dfw : NDFW-4X-000016 - Find DFW default layer 3 rule] ***********************************************************************************************************************************************************
ok: [127.0.0.1] => {"cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": false, "connection": "close", "content_type": "application/json", "cookies": {}, "cookies_string": "", "date": "Mon, 10 Jul 2023 16:49:52 GMT", "elapsed": 0, "expires": "0", "json": {"_create_time": 1688751880285, "_create_user": "system", "_last_modified_time": 1689007787614, "_last_modified_user": "admin", "_protection": "NOT_PROTECTED", "_revision": 1, "_system_owned": false, "action": "ALLOW", "destination_groups": ["ANY"], "destinations_excluded": false, "direction": "IN_OUT", "disabled": false, "display_name": "default-layer3-rule", "id": "default-layer3-rule", "ip_protocol": "IPV4_IPV6", "is_default": true, "logged": true, "marked_for_delete": false, "origin_site_id": "9d96be5a-afca-498c-8c04-8ca4514f7b40", "overridden": false, "owner_id": "9d96be5a-afca-498c-8c04-8ca4514f7b40", "parent_path": "/infra/domains/default/security-policies/default-layer3-section", "path": "/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule", "profiles": ["ANY"], "realization_id": "aa423bd5-1ab7-41b0-958c-aa101f264df6", "relative_path": "default-layer3-rule", "remote_path": "", "resource_type": "Rule", "rule_id": 2, "scope": ["ANY"], "sequence_number": 2147483647, "services": ["ANY"], "source_groups": ["ANY"], "sources_excluded": false, "unique_id": "aa423bd5-1ab7-41b0-958c-aa101f264df6"}, "msg": "OK (unknown bytes)", "pragma": "no-cache", "redirected": false, "server": "envoy", "status": 200, "strict_transport_security": "max-age=31536000; includeSubDomains", "transfer_encoding": "chunked", "url": "https://10.180.98.230/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule", "vary": "Accept-Encoding", "x_content_type_options": "nosniff", "x_envoy_upstream_service_time": "20", "x_frame_options": "SAMEORIGIN", "x_nsx_requestid": "1b66a182-4959-4cbf-8438-ec304ce83c7b", "x_xss_protection": "1; mode=block"}

TASK [dfw : NDFW-4X-000016 - Update DFW default layer 3 rule action to desired value] *********************************************************************************************************************************
changed: [127.0.0.1] => {"cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": true, "connection": "close", "content_length": "0", "cookies": {}, "cookies_string": "", "date": "Mon, 10 Jul 2023 16:49:54 GMT", "elapsed": 0, "expires": "0", "msg": "OK (0 bytes)", "pragma": "no-cache", "redirected": false, "server": "envoy", "status": 200, "strict_transport_security": "max-age=31536000; includeSubDomains", "url": "https://10.180.98.230/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule", "x_content_type_options": "nosniff", "x_envoy_upstream_service_time": "69", "x_frame_options": "SAMEORIGIN", "x_nsx_requestid": "ce242eda-7340-4097-a72c-ff10ae72c4e8", "x_xss_protection": "1; mode=block"}
```

A more conservative and preferred approach is to target any non-compliant controls or run each component separately allowed you to perform any functional testing in between.
```bash
# Providing the tag "dfw" will instruct the playbook to only run the dfw role. This tag can be seen in each roles task/main.yml file.
> ansible-playbook playbook.yml -v --extra-vars @vars-nsx-4.x-example.yml --tags dfw

# Providing the tag " NDFW-4X-000004" will instruct the playbook to only run task tagged with the STIG ID of  NDFW-4X-000004.
> ansible-playbook playbook.yml -v --extra-vars @vars-nsx-4.x-example.yml --tags NDFW-4X-000004
```