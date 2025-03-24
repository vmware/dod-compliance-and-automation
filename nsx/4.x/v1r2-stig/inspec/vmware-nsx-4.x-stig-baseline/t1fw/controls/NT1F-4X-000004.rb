control 'NT1F-4X-000004' do
  title 'The NSX Tier-1 Gateway firewall must generate traffic log entries.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the network element logs provides a means of investigating an attack, recognizing resource usage or capacity thresholds, or identifying an improperly configured network element.

'
  desc 'check', 'From the NSX Manager web interface, go to Security >> Policy Management >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-1 Gateway and for each rule, click the gear icon and verify the logging setting.

If logging is not "Enabled", this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, go to Security >> Policy Management >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-1 Gateway and for each rule with logging disabled, click the gear icon and enable logging, and then click "Apply".

After all changes are made, click "Publish".'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Tier-1 Gateway Firewall'
  tag check_id: 'C-69405r994831_chk'
  tag severity: 'medium'
  tag gid: 'V-265488'
  tag rid: 'SV-265488r994833_rule'
  tag stig_id: 'NT1F-4X-000004'
  tag gtitle: 'SRG-NET-000074-FW-000009'
  tag fix_id: 'F-69313r994832_fix'
  tag satisfies: ['SRG-NET-000074-FW-000009', 'SRG-NET-000061-FW-000001', 'SRG-NET-000075-FW-000010', 'SRG-NET-000076-FW-000011', 'SRG-NET-000077-FW-000012', 'SRG-NET-000078-FW-000013', 'SRG-NET-000492-FW-000006', 'SRG-NET-000493-FW-000007']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000067', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000172']
  tag nist: ['AU-3 a', 'AC-17 (1)', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 c']

  t1s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  describe t1s do
    its('status') { should cmp 200 }
  end
  unless t1s.status != 200
    t1sjson = JSON.parse(t1s.body)
    if t1sjson['results'] == []
      impact 0.0
      describe 'No T1 Gateways are deployed. This is Not Applicable.' do
        skip 'No T1 Gateways are deployed. This is Not Applicable.'
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
