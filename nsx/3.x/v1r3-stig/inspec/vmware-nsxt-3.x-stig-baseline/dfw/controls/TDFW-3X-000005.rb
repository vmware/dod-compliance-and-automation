control 'TDFW-3X-000005' do
  title 'The NSX-T Distributed Firewall must generate traffic log entries containing information to establish the details of the event.'
  desc 'Without sufficient information to analyze the event, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that must be included to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

The NSX-T Distributed Firewall must also generate traffic log records when traffic is denied, restricted, or discarded as well as when attempts are made to send packets between security zones that are not authorized to communicate.

'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> Distributed Firewall >> All Rules. For each rule, click the gear icon and verify the Logging setting.

If Logging is not enabled for any rule, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Distributed Firewall >> Category Specific Rules.

For each rule that has logging disabled, click the gear icon, toggle the logging option to "Enable" and click "Apply".

or

For each Policy or Section, click the menu icon on the left and select "Enable Logging for All Rules".

After all changes are made, click "Publish".'
  impact 0.5
  tag check_id: 'C-55164r810033_chk'
  tag severity: 'medium'
  tag gid: 'V-251727'
  tag rid: 'SV-251727r810035_rule'
  tag stig_id: 'TDFW-3X-000005'
  tag gtitle: 'SRG-NET-000074-FW-000009'
  tag fix_id: 'F-55118r810034_fix'
  tag satisfies: ['SRG-NET-000074-FW-000009', 'SRG-NET-000075-FW-000010', 'SRG-NET-000076-FW-000011', 'SRG-NET-000077-FW-000012', 'SRG-NET-000078-FW-000013', 'SRG-NET-000492-FW-000006', 'SRG-NET-000493-FW-000007']
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000135', 'CCI-000172']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 (1)', 'AU-12 c']

  result = http("https://#{input('nsxManager')}/policy/api/v1/search?query=(resource_type:SecurityPolicy%20AND%20!id:default-layer2-section)",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    policies = JSON.parse(result.body)
    policies['results'].each do |policy|
      poljson = json(content: policy.to_json)
      polpath = poljson['path']
      rulesresult = http("https://#{input('nsxManager')}/policy/api/v1#{polpath}/rules",
                         method: 'GET',
                         headers: {
                           'Accept' => 'application/json',
                           'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                           'Cookie' => "#{input('sessionCookieId')}"
                         },
                         ssl_verify: false)
      rules = JSON.parse(rulesresult.body)
      rules['results'].each do |rule|
        id = rule['id']
        describe json(content: rule.to_json) do
          its('id') { should cmp id }
          its('logged') { should cmp 'true' }
        end
      end
    end
  end
end
