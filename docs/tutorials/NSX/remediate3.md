# Remediate NSX-T 3.x
Remediating NSX-T 3.x for STIG Compliance

## Overview
Remediating NSX-T 3.x for STIG compliance involves configuring the NSX Managers, DFW, and any gateways deployed.  

To remediate NSX-T, Ansible is the automation tool used to interact with the NSX-T REST API.   

## Prerequisites
Versions listed below were used for this documentation. Other versions of these tools may work as well but if issues are found it is recommended to try the versions listed here.  

* The [vmware-nsxt-3.x-stig-ansible-hardening](https://github.com/vmware/dod-compliance-and-automation/tree/master/nsx/3.x/ansible/vmware-nsxt-3.x-stig-ansible-hardening) playbook downloaded.
* Ansible 2.14.4
* Install [JMESPath](https://pypi.org/project/jmespath/) for community.general.json_query collection.
* An NSX-T 3.x environment. 3.2.3 was used in this example.
* An account with sufficient privileges to configure NSX-T.

## Important Considerations
## **⚠️ Please read carefully before proceeding!**

Some NSX-T STIG controls can be very impactful to the environment if care is not taken during implementation especially in a brownfield scenario. For example, changing the default DFW rule to deny traffic without first creating rules to allow authorized traffic.  

Below is a table of controls selected for consideration but all controls should be examined for impact before implementing.  

These can be turned on/off by with a variable that must be set to true as a condition for these tasks to run. See [Update vars file](#update-vars-file) for more details.

| STIG ID | Title | Notes |
|---------|-------|-------|
|TDFW-3X-000019|The NSX-T Distributed Firewall must block outbound traffic containing denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.||
|TDFW-3X-000021|The NSX-T Distributed Firewall must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).|Ensure DFW rules are created to allow authorized traffic.|
|TDFW-3X-000036|The NSX-T Distributed Firewall must configure SpoofGuard to block outbound IP packets that contain illegitimate packet attributes.|Develop an operational plan to manage Spoofguard and identity workloads multiple IPs, etc, that may have issues.|
|T0FW-3X-000019|The NSX-T Tier-0 Gateway Firewall must block outbound traffic containing denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.||
|T0FW-3X-000021|The NSX-T Tier-0 Gateway Firewall must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).|Ensure gateway firewall rules are created to allow authorized traffic.|
|T0FW-3X-000036|The NSX-T Tier-0 Gateway Firewall must configure SpoofGuard to block outbound IP packets that contain illegitimate packet attributes.|Develop an operational plan to manage Spoofguard and identity workloads multiple IPs, etc, that may have issues.|
|T1FW-3X-000019|The NSX-T Tier-1 Gateway Firewall must block outbound traffic containing denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.||
|T1FW-3X-000021|The NSX-T Tier-1 Gateway Firewall must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).|Ensure gateway firewall rules are created to allow authorized traffic.|
|T1FW-3X-000036|The NSX-T Tier-1 Gateway Firewall must configure SpoofGuard to block outbound IP packets that contain illegitimate packet attributes.|Develop an operational plan to manage Spoofguard and identity workloads multiple IPs, etc, that may have issues.|

Also not all controls are covered by the Ansible playbook and may require manual remediation.  

## Remediating NSX-T
To remediate NSX-T an [Ansible playbook](https://github.com/vmware/dod-compliance-and-automation/tree/master/nsx/3.x/ansible/vmware-nsxt-3.x-stig-ansible-hardening) has been provided that will target an NSX-T Manager over the REST API and configure any non-compliant controls.  

Since Ansible can only be run from Linux based systems, the examples below are being run on an Ubuntu 22.04 WSL2 instance on Windows 11 for reference.  

### Generate API Session Token
This playbook uses Session-Based authentication to authenticate with NSX for remediation. A session token and cookie must be generated and provided an input for the profile. This can be generated in various ways via curl, tools like Postman, etc. For more information see the [NSX API Documentation](https://developer.vmware.com/apis/1248/nsx-t).

> **Note:** If the user is a remote user, append "@domain" to the username, for example, "joe@example.com". The domain must match a domain for a configured VIDM identity source or a configured LDAP identity source.  

Curl example:

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

### Update vars file
In order to run the playbook, environment specific values need to be provided. An example vars file `vars-nsxt-3.x-example.yml` is provided and values need to be updated for the `var_nsx_manager`, `var_jsession_id`, `var_session_token`, `var_ntp_server1`, `var_ntp_server2` variables at a minimum.  

```yml
# Manager variables
# NSX Manager IP or FQDN
var_nsx_manager: '10.43.173.83'
# Session cookie id generated for access to NSX. Example 'JSESSIONID=2A165FCF851CA50FCD038DFC8E770038'
var_jsession_id: 'JSESSIONID=77EE4288C048073598F50493167A881A'
# Session token generated for access to NSX
var_session_token: 'cabda93b-f2e9-406d-bcfa-ec56b9a07bce'
# Enter the environment specific time servers.
var_ntp_server1: 'time-a-g.nist.gov'
var_ntp_server2: 'time-b-g.nist.gov'

## Set to true/false to enable or disable controls
# DFW
# TDFW-3X-000002
run_dfw_unpublished_rules: true
# TDFW-3X-000005
run_dfw_rule_logging: true
# TDFW-3X-000019-28
run_dfw_floodprotprof: true
# TDFW-3X-000021 !!Caution if set to true this will set the default DFW rule to DROP!!
run_dfw_default_rule_action: false
var_dfw_default_rule_action_desired: "DROP"
# TDFW-3X-000026
run_dfw_syslog: true
# TDFW-3X-000036
run_dfw_spoofguard_prof: false
# TDFW-3X-000042
run_dfw_verify_time_based_rules: true

# Manager
# TNDM-3X-000012 TNDM-3X-000041
run_mgr_auth_policy: true
# TNDM-3X-000052 TNDM-3X-000080 TNDM-3X-000101
run_mgr_api_session_timeout: true
run_mgr_cli_timeout: true
# TNDM-3X-000068
run_mgr_ntp_servers: true
# TNDM-3X-000069
run_mgr_timezone: true
# TNDM-3X-000083
run_service_log_levels: true
# TNDM-3X-000098
run_mgr_disable_ceip_acceptance: true
# TNDM-3X-000099
run_mgr_disable_ssh: true
# TNDM-3X-000100
run_mgr_disable_local_accounts: true
# TNDM-3X-000103
run_mgr_enable_fips_for_lbs: true

# T0FW
# T0FW-3X-000002
run_t0fw_unpublished_rules: true
# T0FW-3X-000006
run_t0fw_rule_logging: true
# T0FW-3X-000011
run_t0fw_syslog_tls: true
# T0FW-3X-000019-28
run_t0fw_floodprotprof: true
# T0FW-3X-000021
run_t0fw_default_rule_action: false
var_t0fw_default_rule_action_desired: "DROP"
# T0FW-3X-000030
run_t0fw_gwfw_rules: true
# T0FW-3X-000036
run_t0fw_spoofguard_prof: false

# T0RT
# T0RT-3X-000003
run_t0rt_bgp_reject_advertisements: true
# T0RT-3X-000013
run_t0rt_gateway_interface_pim_multicast: true
# array of t0 interface ids that should have multicast enabled
var_t0rt_gateway_interfaces_with_multicast_enabled: []
# T0RT-3X-000016
run_t0rt_remove_inactive_interfaces: true
# T0RT-3X-000027
run_t0rt_disable_dhcp: true
# array of t0 ids that should have dhcp enabled
var_t0rt_gateways_with_dhcp_enabled: []
# T0RT-3X-000034
run_t0rt_qos_segment_profile: true
# T0RT-3X-000038
run_t0rt_restrict_traffic: true
# T0RT-3X-000051
run_t0rt_gateway_urpf: true
# T0RT-3X-000054
run_t0rt_auth_routing_protocols: true
# T0RT-3X-000055
run_t0rt_uniq_key_per_as: true
# T0RT-3X-000064,65,66
run_t0rt_gateway_icmp: true
# T0RT-3X-000067
run_t0rt_bgp_nbr_maxroutes: true
var_t0rt_upd_bgp_nbr_route_filter_max_routes: 200
# T0RT-3X-000084
run_t0rt_loopback_source_ibgp: true
# T0RT-3X-000095
run_t0rt_gateway_bgp_ospf: true
# T0RT-3X-000096
run_t0rt_gateway_multicast: true
# array of t0 ids that should have multicast enabled
var_t0rt_gateways_with_multicast_enabled: []

# T1FW
# T1FW-3X-000002
run_t1fw_unpublished_rules: true
# T1FW-3X-000005-06
run_t1fw_rule_logging: true
# T1FW-3X-000011-26
run_t1fw_syslog_tls: true
# T1FW-3X-000019-28
run_t1fw_floodprotprof: true
# T1FW-3X-000021
run_t1fw_default_rule_action: false
var_t1fw_default_rule_action_desired: "DROP"
# T1FW-3X-000030
run_t1fw_gwfw_rules: true
# T1FW-3X-000036
run_t1fw_spoofguard_prof: false

# T1RT
# T1RT-3X-000016
run_t1rt_remove_inactive_interfaces: true
# T1RT-3X-000027
run_t1rt_disable_dhcp: true
# array of t1 ids that should have dhcp enabled
var_t1rt_gateways_with_dhcp_enabled: []
# T1RT-3X-000034
run_t1rt_qos: true
# T1RT-3X-000084
run_t1rt_gateway_multicast: true
# array of t1 ids that should have multicast enabled
var_t1rt_gateways_with_multicast_enabled: []
```

### Running the playbook
To run all of the NSX-T controls, follow the example below.

```bash
# The -k parameter will prompt for password and we are using extra-vars to specify a variable file for the playbook to use. Command assumes it is being ran from the playbook folder.
> ansible-playbook playbook.yml -v --extra-vars @vars-nsxt-3.x-example.yml

# Output example
PLAY [NSX-T 3.x Remediation Automation] ***************************************************************************************************************************************************************************************

TASK [dfw : Include DFW] ******************************************************************************************************************************************************************************************************
included: /mnt/c/gitlab/vmware-nsxt-3.x-stig-ansible-hardening/roles/dfw/tasks/dfw.yml for 127.0.0.1

TASK [dfw : TDFW-3X-000005 - Find DFW rules without logging enabled excluding the default layer 2 rule] ***********************************************************************************************************************
ok: [127.0.0.1] => {"cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": false, "connection": "close", "content_type": "application/json", "cookies": {}, "cookies_string": "", "date": "Fri, 07 Jul 2023 01:04:54 GMT", "elapsed": 0, "expires": "0", "json": {"cursor": "3", "result_count": 3, "results": [{"action": "ALLOW", "id": "default-layer3-rule", "logged": false, "path": "/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule", "rule_id": 2, "sequence_number": 2147483647}, {"action": "ALLOW", "id": "default_rule_DHCP", "logged": false, "path": "/infra/domains/default/security-policies/default-layer3-section/rules/default_rule_DHCP", "rule_id": 4, "sequence_number": 50000}, {"action": "ALLOW", "id": "default_rule_NDP", "logged": false, "path": "/infra/domains/default/security-policies/default-layer3-section/rules/default_rule_NDP", "rule_id": 3, "sequence_number": 25000}]}, "msg": "OK (unknown bytes)", "pragma": "no-cache", "redirected": false, "server": "NSX", "status": 200, "strict_transport_security": "max-age=31536000 ; includeSubDomains", "transfer_encoding": "chunked", "url": "https://10.43.173.83/policy/api/v1/search?query=(resource_type:Rule%20AND%20logged:false%20AND%20!id:default-layer2-rule%20AND%20parent_path:?infra?domains?default?security-policies*)&included_fields=id,rule_id,logged,path,sequence_number,action", "vary": "accept-encoding", "x_content_type_options": "nosniff", "x_frame_options": "SAMEORIGIN", "x_nsx_requestid": "dfc6dbcf-e0df-4893-ad42-29c7b5a55c40", "x_xss_protection": "1; mode=block"}

TASK [dfw : TDFW-3X-000005 - Enable logging on DFW rules without logging enabled excluding the default layer 2 rule] **********************************************************************************************************
changed: [127.0.0.1] => (item={'rule_id': 2, 'sequence_number': 2147483647, 'path': '/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule', 'logged': False, 'action': 'ALLOW', 'id': 'default-layer3-rule'}) => {"ansible_loop_var": "item", "cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": true, "connection": "close", "content_length": "0", "cookies": {}, "cookies_string": "", "date": "Fri, 07 Jul 2023 01:04:56 GMT", "elapsed": 1, "expires": "0", "item": {"action": "ALLOW", "id": "default-layer3-rule", "logged": false, "path": "/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule", "rule_id": 2, "sequence_number": 2147483647}, "msg": "OK (0 bytes)", "pragma": "no-cache", "redirected": false, "server": "NSX", "status": 200, "strict_transport_security": "max-age=31536000 ; includeSubDomains", "url": "https://10.43.173.83/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule", "x_content_type_options": "nosniff", "x_frame_options": "SAMEORIGIN", "x_nsx_requestid": "9d03bce2-d284-46b6-8898-c12d6003f453", "x_xss_protection": "1; mode=block"}
changed: [127.0.0.1] => (item={'rule_id': 4, 'sequence_number': 50000, 'path': '/infra/domains/default/security-policies/default-layer3-section/rules/default_rule_DHCP', 'logged': False, 'action': 'ALLOW', 'id': 'default_rule_DHCP'}) => {"ansible_loop_var": "item", "cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": true, "connection": "close", "content_length": "0", "cookies": {}, "cookies_string": "", "date": "Fri, 07 Jul 2023 01:04:57 GMT", "elapsed": 0, "expires": "0", "item": {"action": "ALLOW", "id": "default_rule_DHCP", "logged": false, "path": "/infra/domains/default/security-policies/default-layer3-section/rules/default_rule_DHCP", "rule_id": 4, "sequence_number": 50000}, "msg": "OK (0 bytes)", "pragma": "no-cache", "redirected": false, "server": "NSX", "status": 200, "strict_transport_security": "max-age=31536000 ; includeSubDomains", "url": "https://10.43.173.83/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules/default_rule_DHCP", "x_content_type_options": "nosniff", "x_frame_options": "SAMEORIGIN", "x_nsx_requestid": "16ecd5a7-2b74-4255-8e2e-a16d4c33f076", "x_xss_protection": "1; mode=block"}
changed: [127.0.0.1] => (item={'rule_id': 3, 'sequence_number': 25000, 'path': '/infra/domains/default/security-policies/default-layer3-section/rules/default_rule_NDP', 'logged': False, 'action': 'ALLOW', 'id': 'default_rule_NDP'}) => {"ansible_loop_var": "item", "cache_control": "no-cache, no-store, max-age=0, must-revalidate", "changed": true, "connection": "close", "content_length": "0", "cookies": {}, "cookies_string": "", "date": "Fri, 07 Jul 2023 01:04:57 GMT", "elapsed": 0, "expires": "0", "item": {"action": "ALLOW", "id": "default_rule_NDP", "logged": false, "path": "/infra/domains/default/security-policies/default-layer3-section/rules/default_rule_NDP", "rule_id": 3, "sequence_number": 25000}, "msg": "OK (0 bytes)", "pragma": "no-cache", "redirected": false, "server": "NSX", "status": 200, "strict_transport_security": "max-age=31536000 ; includeSubDomains", "url": "https://10.43.173.83/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules/default_rule_NDP", "x_content_type_options": "nosniff", "x_frame_options": "SAMEORIGIN", "x_nsx_requestid": "88ad2a48-7039-41d6-a758-84999467a2b3", "x_xss_protection": "1; mode=block"}
```

A more conservative and preferred approach is to target any non-compliant controls, or run each component separately, allowing for performing any functional testing in between.

```bash
# Providing the tag "dfw" will instruct the playbook to only run the dfw role. This tag can be seen in each roles task/main.yml file.
> ansible-playbook playbook.yml -v --extra-vars @vars-nsxt-3.x-example.yml --tags dfw

# Providing the tag " TDFW-3X-000005" will instruct the playbook to only run task tagged with the STIG ID of  TDFW-3X-000005.
> ansible-playbook playbook.yml -v --extra-vars @vars-nsxt-3.x-example.yml --tags TDFW-3X-000005
```
