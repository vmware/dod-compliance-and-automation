control 'NDFW-4X-000004' do
  title 'The NSX Distributed Firewall must generate traffic log entries.'
  desc  "
    Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

    Audit event content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the network element logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to Security >> Policy Management >> Distributed Firewall >> All Rules.

    For each rule, click the gear icon and verify the Logging setting.

    If Logging is not enabled for any rule, this is a finding.
  "
  desc 'fix', "
    From the NSX Manager web interface, go to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules.

    For each rule that has logging disabled, click the gear icon, toggle the logging option to \"Enable\" and click \"Apply\".

    or

    For each Policy or Section, click the menu icon on the left and select \"Enable Logging for All Rules\".

    After all changes are made, click \"Publish\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000074-FW-000009'
  tag satisfies: ['SRG-NET-000075-FW-000010', 'SRG-NET-000076-FW-000011', 'SRG-NET-000077-FW-000012', 'SRG-NET-000078-FW-000013', 'SRG-NET-000492-FW-000006', 'SRG-NET-000493-FW-000007']
  tag gid: 'V-NDFW-4X-000004'
  tag rid: 'SV-NDFW-4X-000004'
  tag stig_id: 'NDFW-4X-000004'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000172']
  tag nist: ['AU-12 c', 'AU-3']

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
