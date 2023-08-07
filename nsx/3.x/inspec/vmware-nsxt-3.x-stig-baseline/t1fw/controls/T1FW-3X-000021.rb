control 'T1FW-3X-000021' do
  title 'The NSX-T Tier-1 Gateway Firewall must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).'
  desc 'To prevent malicious or accidental leakage of traffic, organizations must implement a deny-by-default security posture at the network perimeter. Such rulesets prevent many malicious exploits or accidental leakage by restricting the traffic to only known sources and only those ports, protocols, or services that are permitted and operationally necessary. This configuration which is in the Manager function of the NSX-T implementation also helps prevent the firewall instance from failing to a state that may cause unauthorized access to make changes to the firewall filtering functions.

As a managed boundary interface, the firewall must block all inbound and outbound network traffic unless a filter is installed to explicitly allow it. The allow filters must comply with the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and Vulnerability Assessment (VA).

'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules >> Choose each Tier-1 Gateway in drop-down >> Policy_Default_Infra Section >> Action.

If the default_rule is set to Allow, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules >> Choose each Tier-1 Gateway in drop-down >> Policy_Default_Infra Section >> Action >> change the Action to Drop or Reject and click Publish.'
  impact 0.5
  tag check_id: 'C-55202r810188_chk'
  tag severity: 'medium'
  tag gid: 'V-251765'
  tag rid: 'SV-251765r810190_rule'
  tag stig_id: 'T1FW-3X-000021'
  tag gtitle: 'SRG-NET-000202-FW-000039'
  tag fix_id: 'F-55156r810189_fix'
  tag satisfies: ['SRG-NET-000235-FW-000133', 'SRG-NET-000236-FW-000027']
  tag cci: ['CCI-001109', 'CCI-001190', 'CCI-001665']
  tag nist: ['SC-7 (5)', 'SC-24', 'SC-24']

  t1s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
                },
              ssl_verify: false)

  describe t1s do
    its('status') { should cmp 200 }
  end
  unless t1s.status != 200
    t1sjson = JSON.parse(t1s.body)
    if t1sjson['results'] == []
      describe 'No T0 Gateways are deployed...skipping...' do
        skip 'No T0 Gateways are deployed...skipping...'
      end
    else
      t1sjson['results'].each do |t1|
        t1json = json(content: t1.to_json)
        t1id = t1json['id']
        defaultrule = http("https://#{input('nsxManager')}/policy/api/v1/infra/domains/default/gateway-policies/Policy_Default_Infra-tier1-#{t1id}/rules/default_rule",
                          method: 'GET',
                          headers: {
                            'Accept' => 'application/json',
                            'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                            'Cookie' => "#{input('sessionCookieId')}",
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
