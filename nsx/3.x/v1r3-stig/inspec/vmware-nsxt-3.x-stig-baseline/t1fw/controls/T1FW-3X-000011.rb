control 'T1FW-3X-000011' do
  title 'Each NSX-T Edge Node configured to host a Tier-1 Gateway Firewall must be configured to use the TLS or LI-TLS protocols to configure and secure traffic log records.'
  desc 'It is critical that when the network element is at risk of failing to process traffic logs as required, it takes action to mitigate the failure, secure collected log data, and  restrict access to authorized personnel. Methods of protection may include encryption or logical separation.

In accordance with DOD policy, the traffic log must be sent to a central audit server.

This does not apply to traffic logs generated on behalf of the device itself (management). Some devices store traffic logs separately from the system logs.

'
  desc 'check', 'From an NSX-T Edge Node shell hosting the Tier-1 Gateway, run the following command(s):

> get logging-servers

If any configured logging-servers are not configured with protocol of "li-tls" or "tls" and level of "info", this is a finding.

If no logging-servers are configured, this is a finding.

Note: This check must be run from each NSX-T Edge Node hosting the Tier-1 Gateway, as they are configured individually.'
  desc 'fix', '(Optional) From an NSX-T Edge Gateway shell, run the following command(s) to clear any existing incorrect logging-servers:

> clear logging-servers

From an NSX-T Edge Node shell, run the following command(s) to configure a tls syslog server:

> set logging-server <server-ip or server-name> proto tls level info serverca ca.pem clientca ca.pem certificate cert.pem key key.pem

From an NSX-T Edge Node shell, run the following command(s) to configure a li-tls syslog server:

> set logging-server <server-ip or server-name> proto li-tls level info serverca root-ca.crt

Note: If using the protocols TLS or LI-TLS to configure a secure connection to a log server, the server and client certificates must be stored in /var/vmware/nsx/file-store/ on each NSX-T Edge Gateway appliance.'
  impact 0.5
  tag check_id: 'C-55200r919236_chk'
  tag severity: 'medium'
  tag gid: 'V-251763'
  tag rid: 'SV-251763r919237_rule'
  tag stig_id: 'T1FW-3X-000011'
  tag gtitle: 'SRG-NET-000089-FW-000019'
  tag fix_id: 'F-55154r810183_fix'
  tag satisfies: ['SRG-NET-000089-FW-000019', 'SRG-NET-000098-FW-000021']
  tag cci: ['CCI-000140', 'CCI-000162']
  tag nist: ['AU-5 b', 'AU-9 a']

  edgetns = http("https://#{input('nsxManager')}/policy/api/v1/search?query=( resource_type:TransportNode AND node_deployment_info.resource_type:EdgeNode )",
                 method: 'GET',
                 headers: {
                   'Accept' => 'application/json',
                   'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                   'Cookie' => "#{input('sessionCookieId')}"
                 },
                 ssl_verify: false)

  describe edgetns do
    its('status') { should cmp 200 }
  end
  unless edgetns.status != 200
    tnsjson = JSON.parse(edgetns.body)
    if tnsjson['results'] == []
      describe 'No Edge Transport Nodes are deployed...skipping...' do
        skip 'No Edge Transport Nodes are deployed...skipping...'
      end
    else
      tnsjson['results'].each do |tn|
        tnjson = json(content: tn.to_json)
        tnid = tnjson['id']
        tnsyslog = http("https://#{input('nsxManager')}/api/v1/transport-nodes/#{tnid}/node/services/syslog/exporters",
                        method: 'GET',
                        headers: {
                          'Accept' => 'application/json',
                          'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                          'Cookie' => "#{input('sessionCookieId')}"
                        },
                        ssl_verify: false)

        describe tnsyslog do
          its('status') { should cmp 200 }
        end
        next unless tnsyslog.status == 200
        logservers = JSON.parse(tnsyslog.body)
        if logservers['results'] == []
          describe "No syslog servers are configured on Edge Node: #{tnjson['display_name']}" do
            subject { logservers['results'] }
            it { should_not cmp [] }
          end
        else
          logservers['results'].each do |logserver|
            describe json(content: logserver.to_json) do
              its('level') { should cmp 'INFO' }
              its('protocol') { should be_in ['TLS', 'LI-TLS'] }
              its('server') { should be_in "#{input('syslogServers')}" }
            end
          end
        end
      end
    end
  end
end
