control 'NDFW-4X-000008' do
  title 'The NSX Distributed Firewall must generate traffic log entries containing information to establish the outcome of the events, such as, at a minimum, the success or failure of the application of the NSX Distributed Firewall rule.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results. They also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'From the NSX Manager web interface, navigate to Security >> Policy Management >> Distributed Firewall >> All Rules.

For each rule, click the gear icon and verify the logging setting.

If logging is not enabled for any rule, this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, navigate to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules.

For each rule that has logging disabled, click the gear icon, toggle the logging option to "Enable" and click "Apply".

or

For each Policy or Section, click the menu icon on the left and select "Enable Logging for All Rules".

After all changes are made, click "Publish".'
  impact 0.5
  tag check_id: 'C-67077r977296_chk'
  tag severity: 'medium'
  tag gid: 'V-263177'
  tag rid: 'SV-263177r977298_rule'
  tag stig_id: 'NDFW-4X-000008'
  tag gtitle: 'SRG-NET-000078-FW-000013'
  tag fix_id: 'F-66985r977297_fix'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']

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
