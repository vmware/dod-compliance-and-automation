control 'T1FW-3X-000030' do
  title 'The NSX-T Tier-1 Gateway Firewall must apply ingress filters to traffic that is inbound to the network through any active external interface.'
  desc 'Unrestricted traffic to the trusted networks may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Firewall filters control the flow of network traffic and ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the internet) must be kept separated.'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules. Choose each Tier-1 Gateway in the drop-down and review the firewall rules "Applied To" field to verify no rules are selectively applied to interfaces instead of the Gateway Firewall entity.

If any Gateway Firewall rules are applied to individual interfaces, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules and choose the target Tier-1 Gateway from the drop-down.

For any rules that have individual interfaces specified in the "Applied To" field, click "Edit" on the "Applied To" column and remove the interfaces selected, leaving only the Tier-1 Gateway object type checked.

Click "Publish" to save any rule changes.'
  impact 0.5
  tag check_id: 'C-55205r810197_chk'
  tag severity: 'medium'
  tag gid: 'V-251768'
  tag rid: 'SV-251768r856687_rule'
  tag stig_id: 'T1FW-3X-000030'
  tag gtitle: 'SRG-NET-000364-FW-000031'
  tag fix_id: 'F-55159r810198_fix'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']

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
        firewallresult = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s/#{t1id}/gateway-firewall",
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
              its('scope') { should cmp ["/infra/tier-1s/#{t1id}"] }
            end
          end
        end
      end
    end
  end
end
