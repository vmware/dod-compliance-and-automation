control 'T0FW-3X-000030' do
  title 'The NSX-T Tier-0 Gateway Firewall must apply ingress filters to traffic that is inbound to the network through any active external interface.'
  desc 'Unrestricted traffic to the trusted networks may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Firewall filters control the flow of network traffic, ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the internet) must be kept separated.'
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode and no stateless rules exist, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules. Choose each T0-Gateway in the drop-down and review the firewall rules "Applied To" field to verify no rules are selectively applied to interfaces instead of the Gateway Firewall entity.

If any Gateway Firewall rules are applied to individual interfaces, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules and choose the target Tier-0 Gateway from the drop-down.

For any rules that have individual interfaces specified in the "Applied To" field, click "Edit" in the "Applied To" column and remove the interfaces selected, leaving only the Tier-0 Gateway object type checked.

Click "Publish" to save any rule changes.'
  impact 0.5
  tag check_id: 'C-55179r810091_chk'
  tag severity: 'medium'
  tag gid: 'V-251742'
  tag rid: 'SV-251742r856691_rule'
  tag stig_id: 'T0FW-3X-000030'
  tag gtitle: 'SRG-NET-000364-FW-000031'
  tag fix_id: 'F-55133r810092_fix'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']

  t0s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
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
                'Cookie' => "#{input('sessionCookieId')}",
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
              its('scope') { should cmp ["/infra/tier-0s/#{t0id}"] }
            end
          end
        end
      end
    end
  end
end
