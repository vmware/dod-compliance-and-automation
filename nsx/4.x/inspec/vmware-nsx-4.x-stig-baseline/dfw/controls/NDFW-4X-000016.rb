control 'NDFW-4X-000016' do
  title 'The NSX Distributed Firewall must deny network communications traffic by default and allow network communications traffic by exception.'
  desc  "
    To prevent malicious or accidental leakage of traffic, organizations must implement a deny-by-default security posture at the network perimeter. Such rulesets prevent many malicious exploits or accidental leakage by restricting the traffic to only known sources and only those ports, protocols, or services that are permitted and operationally necessary.

    As a managed boundary interface, the firewall must block all inbound and outbound network traffic unless a filter is installed to explicitly allow it. The allow filters must comply with the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and Vulnerability Assessment (VA).
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules >> APPLICATION >> Default Layer3 Section >> Default Layer3 Rule >> Action.

    If the Default Layer3 Rule is set to \"ALLOW\", this is a finding.
  "
  desc 'fix', "
    From the NSX Manager web interface, go to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules >> APPLICATION >> Default Layer3 Section >> Default Layer3 Rule and change action to \"Drop\" or \"Reject\".

    After all changes are made, click \"Publish\".

    Note: Before enabling, ensure the necessary rules to whitelist approved traffic are created and published or this change may result in loss of communication for workloads.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-NET-000202-FW-000039'
  tag satisfies: ['SRG-NET-000235-FW-000133']
  tag gid: 'V-NDFW-4X-000016'
  tag rid: 'SV-NDFW-4X-000016'
  tag stig_id: 'NDFW-4X-000016'
  tag cci: ['CCI-001109', 'CCI-001190']
  tag nist: ['SC-24', 'SC-7 (5)']

  result = http("https://#{input('nsxManager')}/policy/api/v1/infra/domains/default/security-policies/default-layer3-section/rules/default-layer3-rule",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('action') { should_not cmp 'ALLOW' }
    end
  end
end
