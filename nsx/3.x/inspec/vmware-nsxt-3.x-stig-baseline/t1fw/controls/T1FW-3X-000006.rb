control 'T1FW-3X-000006' do
  title 'The NSX-T Tier-1 Gateway Firewall must generate traffic log entries containing information to establish the details of the event.'
  desc 'Without sufficient information to analyze the event, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that must be included to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

The firewall must also generate traffic log records when traffic is denied, restricted, or discarded as well as when attempts are made to send packets between security zones that are not authorized to communicate.

'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-1 Gateway and for each rule, click the gear icon and verify the Logging setting.

If Logging is not "Enabled", this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-1 Gateway and for each rule with logging disabled, click the gear icon and enable Logging and then click "Apply".

After all changes are made, click "Publish".'
  impact 0.3
  tag check_id: 'C-55199r919233_chk'
  tag severity: 'low'
  tag gid: 'V-251762'
  tag rid: 'SV-251762r919235_rule'
  tag stig_id: 'T1FW-3X-000006'
  tag gtitle: 'SRG-NET-000075-FW-000010'
  tag fix_id: 'F-55153r919234_fix'
  tag satisfies: ['SRG-NET-000075-FW-000010', 'SRG-NET-000076-FW-000011', 'SRG-NET-000077-FW-000012', 'SRG-NET-000078-FW-000013', 'SRG-NET-000399-FW-000008', 'SRG-NET-000492-FW-000006', 'SRG-NET-000493-FW-000007']
  tag cci: ['CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000172', 'CCI-001462']
  tag nist: ['AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 c', 'AU-14 (2)']

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
      describe 'No T1 Gateways are deployed...skipping...' do
        skip 'No T1 Gateways are deployed...skipping...'
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
              its('logged') { should cmp 'true' }
            end
          end
        end
      end
    end
  end
end
