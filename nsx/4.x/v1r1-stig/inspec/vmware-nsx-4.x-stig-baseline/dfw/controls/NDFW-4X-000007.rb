control 'NDFW-4X-000007' do
  title 'The NSX Distributed Firewall must generate traffic log entries containing information to establish the source of the events, such as the source IP address at a minimum.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. To compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the traffic log events must also identify sources of events, such as IP addresses, processes, and node or device names.'
  desc 'check', 'From the NSX Manager web interface, navigate to Security >> Policy Management >> Distributed Firewall >> All Rules.

For each rule, click the gear icon and verify the logging setting.

If logging is not enabled for any rule, this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, navigate to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules.

For each rule that has logging disabled, click the gear icon, toggle the logging option to "Enable" and click "Apply".

or

For each Policy or Section, click the menu icon on the left and select "Enable Logging for All Rules".

After all changes are made, click "Publish".'
  impact 0.5
  tag check_id: 'C-67076r977293_chk'
  tag severity: 'medium'
  tag gid: 'V-263176'
  tag rid: 'SV-263176r977295_rule'
  tag stig_id: 'NDFW-4X-000007'
  tag gtitle: 'SRG-NET-000077-FW-000012'
  tag fix_id: 'F-66984r977294_fix'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']

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
