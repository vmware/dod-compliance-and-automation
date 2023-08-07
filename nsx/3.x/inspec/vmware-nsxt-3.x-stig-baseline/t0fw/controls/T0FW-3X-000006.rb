control 'T0FW-3X-000006' do
  title 'The NSX-T Tier-0 Gateway Firewall must generate traffic log entries containing information to establish the details of the event.'
  desc 'Without sufficient information to analyze the event, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that must be included to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

The Firewall must also generate traffic log records when traffic is denied, restricted, or discarded as well as when attempts are made to send packets between security zones that are not authorized to communicate.

'
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode and no stateless rules exist, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-0 Gateway and for each rule, click the gear icon and verify the Logging setting.

If Logging is not Enabled, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-0 Gateway and for each rule with logging disabled, click the gear icon, enable Logging, and then click "Apply".

After all changes are made, click "Publish".'
  impact 0.3
  tag check_id: 'C-55174r810076_chk'
  tag severity: 'low'
  tag gid: 'V-251737'
  tag rid: 'SV-251737r810078_rule'
  tag stig_id: 'T0FW-3X-000006'
  tag gtitle: 'SRG-NET-000074-FW-000009'
  tag fix_id: 'F-55128r810077_fix'
  tag satisfies: ['SRG-NET-000074-FW-000009', 'SRG-NET-000075-FW-000010', 'SRG-NET-000076-FW-000011', 'SRG-NET-000077-FW-000012', 'SRG-NET-000078-FW-000013', 'SRG-NET-000399-FW-000008', 'SRG-NET-000492-FW-000006', 'SRG-NET-000493-FW-000007']
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000172', 'CCI-001462']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 c', 'AU-14 (2)']

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
              its('logged') { should cmp 'true' }
            end
          end
        end
      end
    end
  end
end
