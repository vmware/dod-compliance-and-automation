control 'NDFW-4X-000004' do
  title 'The NSX Distributed Firewall must generate traffic log entries that can be sent by the ESXi hosts to the central syslog.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit event content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the network element logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

'
  desc 'check', 'From the NSX Manager web interface, navigate to Security >> Policy Management >> Distributed Firewall >> All Rules.

For each rule, click the gear icon and verify the logging setting.

If logging is not enabled for any rule, this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, navigate to Security >> Policy Management >> Distributed Firewall >> Category Specific Rules.

For each rule that has logging disabled, click the gear icon, toggle the logging option to "Enable", and click "Apply".

or

For each Policy or Section, click the menu icon on the left and select "Enable Logging for All Rules".

After all changes are made, click "Publish".

NOTE: Syslog and alert monitoring procedure: Syslog configuration is in the vSphere ESXi STIG where there is a control to require syslog configuration. This is because the NSX Distributed Firewall data plane is not directly configured to communicate with the central log server/syslog. The firewall runs in a distributed manner across ESXi hosts, and the traffic logs for the DFW are located on each host for the traffic it processes and are forwarded from each host to a centralized syslog server. Thus, ESXi hosts must be configured to send the syslogs to the log server. In turn, the syslog must be configured to send all required alerts, including when unknown or out-of-order extension headers are detected in inbound and outbound IPv6 traffic.'
  impact 0.3
  ref 'DPMS Target VMware NSX 4.x Distributed Firewall'
  tag check_id: 'C-69529r993931_chk'
  tag severity: 'low'
  tag gid: 'V-265612'
  tag rid: 'SV-265612r993933_rule'
  tag stig_id: 'NDFW-4X-000004'
  tag gtitle: 'SRG-NET-000074-FW-000009'
  tag fix_id: 'F-69437r993932_fix'
  tag satisfies: ['SRG-NET-000074-FW-000009', 'SRG-NET-000075-FW-000010', 'SRG-NET-000076-FW-000011', 'SRG-NET-000077-FW-000012', 'SRG-NET-000078-FW-000013', 'SRG-NET-000492-FW-000006', 'SRG-NET-000493-FW-000007']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000172']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-12 c']

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
