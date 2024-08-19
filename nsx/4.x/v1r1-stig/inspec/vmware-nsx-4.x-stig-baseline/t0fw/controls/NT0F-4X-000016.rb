control 'NT0F-4X-000016' do
  title 'The NSX Tier-0 Gateway Firewall must deny network communications traffic by default and allow network communications traffic by exception.'
  desc '
    To prevent malicious or accidental leakage of traffic, organizations must implement a deny-by-default security posture at the network perimeter. Such rulesets prevent many malicious exploits or accidental leakage by restricting the traffic to only known sources and only those ports, protocols, or services that are permitted and operationally necessary.

    As a managed boundary interface, the firewall must block all inbound and outbound network traffic unless a filter is installed to explicitly allow it. The allow filters must comply with the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and Vulnerability Assessment (VA).
  '
  desc 'check', '
    From the NSX Manager web interface, go to Security >> Policy Management >> Gateway Firewall >> Gateway Specific Rules.

    Choose each Tier-0 Gateway in drop-down, then select Policy_Default_Infra Section >> Action.

    If the default_rule is set to "Allow", this is a finding.
  '
  desc 'fix', '
    From the NSX Manager web interface, go to Security >> Policy Management >> Gateway Firewall >> Gateway Specific Rules.

    Choose each Tier-0 Gateway in drop-down, then select Policy_Default_Infra Section >> Action.

    Change the Action to "Drop" or "Reject", and then click "Publish".
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000202-FW-000039'
  tag satisfies: ['SRG-NET-000205-FW-000040', 'SRG-NET-000235-FW-000133', 'SRG-NET-000364-FW-000031']
  tag gid: 'V-263280'
  tag rid: 'SV-263280r977607_rule'
  tag stig_id: 'NT0F-4X-000016'
  tag cci: ['CCI-001097', 'CCI-001109', 'CCI-001190', 'CCI-002403']
  tag nist: ['SC-24', 'SC-7 (11)', 'SC-7 (5)', 'SC-7 a']

  t0s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  describe t0s do
    its('status') { should cmp 200 }
  end
  unless t0s.status != 200
    t0sjson = JSON.parse(t0s.body)
    if t0sjson['results'] == []
      impact 0.0
      describe 'No T0 Gateways are deployed. This is Not Applicable.' do
        skip 'No T0 Gateways are deployed. This is Not Applicable.'
      end
    else
      t0sjson['results'].each do |t0|
        t0json = json(content: t0.to_json)
        t0id = t0json['id']
        defaultrule = http("https://#{input('nsxManager')}/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier0-#{t0id}/rules/default_rule",
                           method: 'GET',
                           headers: {
                             'Accept' => 'application/json',
                             'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                             'Cookie' => "#{input('sessionCookieId')}"
                           },
                           ssl_verify: false)

        describe defaultrule do
          its('status') { should cmp 200 }
        end
        next unless defaultrule.status == 200
        describe json(content: defaultrule.body) do
          its('action') { should_not cmp 'ALLOW' }
        end
      end
    end
  end
end
