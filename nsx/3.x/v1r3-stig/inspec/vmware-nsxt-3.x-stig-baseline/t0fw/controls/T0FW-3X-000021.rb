control 'T0FW-3X-000021' do
  title 'The NSX-T Tier-1 Gateway Firewall must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).'
  desc 'To prevent malicious or accidental leakage of traffic, organizations must implement a deny-by-default security posture at the network perimeter. Such rulesets prevent many malicious exploits or accidental leakage by restricting the traffic to only known sources and only those ports, protocols, or services that are permitted and operationally necessary. This configuration, which is in the Manager function of the NSX-T implementation, helps prevent the firewall instance from failing to a state that may cause unauthorized access to make changes to the firewall filtering functions.

As a managed boundary interface, the firewall must block all inbound and outbound network traffic unless a filter is installed to explicitly allow it. The configured filters must comply with the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and Vulnerability Assessment (VA).

'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules. Choose each Tier-1 Gateway in drop-down, then select Policy_Default_Infra Section >> Action.

If the default_rule is set to "Allow", this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules. Choose each Tier-1 Gateway in drop-down, then select Policy_Default_Infra Section >> Action. Change the Action to "Drop" or "Reject", and then click "Publish".'
  impact 0.5
  tag check_id: 'C-55177r810085_chk'
  tag severity: 'medium'
  tag gid: 'V-251740'
  tag rid: 'SV-251740r810087_rule'
  tag stig_id: 'T0FW-3X-000021'
  tag gtitle: 'SRG-NET-000202-FW-000039'
  tag fix_id: 'F-55131r810086_fix'
  tag satisfies: ['SRG-NET-000202-FW-000039', 'SRG-NET-000235-FW-000133', 'SRG-NET-000236-FW-000027', 'SRG-NET-000205-FW-000040']
  tag cci: ['CCI-001097', 'CCI-001109', 'CCI-001190', 'CCI-001665']
  tag nist: ['SC-7 a', 'SC-7 (5)', 'SC-24', 'SC-24']

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
      describe 'No T0 Gateways are deployed...skipping...' do
        skip 'No T0 Gateways are deployed...skipping...'
      end
    else
      t0sjson['results'].each do |t0|
        t0json = json(content: t0.to_json)
        t0id = t0json['id']
        firewallresult = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/gateway-firewall",
                              method: 'GET',
                              headers: {
                                'Accept' => 'application/json',
                                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                                'Cookie' => "#{input('sessionCookieId')}"
                              },
                              ssl_verify: false)

        describe firewallresult do
          its('status') { should cmp 200 }
        end
        next unless firewallresult.status == 200
        firewallpolicies = JSON.parse(firewallresult.body)
        firewallpolicies['results'].each do |firewallpolicy|
          firewallpolicy['rules'].each do |rule|
            id = rule['id']
            describe json(content: rule.to_json) do
              its('id') { should cmp id }
              its('logged') { should cmp 'true' }
            end
          end
        end
      end
    end
  end
end
