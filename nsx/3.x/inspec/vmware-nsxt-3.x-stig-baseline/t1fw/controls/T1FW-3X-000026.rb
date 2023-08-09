control 'T1FW-3X-000026' do
  title 'The NSX-T Tier-1 Gateway Firewall must be configured to send traffic log entries to a central audit server for management and configuration of the traffic log entries.'
  desc 'Without the ability to centrally manage the content captured in the traffic log entries, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. Network components requiring centralized traffic log management must have the ability to support centralized management. The content captured in traffic log entries must be managed from a central location (necessitating automation). Centralized management of traffic log records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

Ensure at least one syslog server is configured on the firewall.

If the product inherently has the ability to store log records locally, the local log must also be secured. However, this requirement is not met since it calls for a use of a central audit server.'
  desc 'check', 'Note: This check must be run from each NSX-T Edge Node hosting the Tier-1 Gateway, as they are configured individually.

From an NSX-T Edge Node shell hosting the Tier-1 Gateway, run the following command(s):

> get logging-servers

If any configured logging-servers are not configured with protocol of "li-tls" or "tls" and level of "info", this is a finding.

If no logging-servers are configured, this is a finding.'
  desc 'fix', '(Optional) From an NSX-T Edge Gateway shell, run the following command(s) to clear any existing incorrect logging-servers:

> clear logging-servers

From an NSX-T Edge Node shell, run the following command(s) to configure a tls syslog server:

> set logging-server <server-ip or server-name> proto tls level info serverca ca.pem clientca ca.pem certificate cert.pem key key.pem

From an NSX-T Edge Node shell, run the following command(s) to configure a li-tls syslog server:

> set logging-server <server-ip or server-name> proto li-tls level info serverca root-ca.crt

Note: Configure the syslog or SNMP server to send an alert if the events server is unable to receive events from the NSX-T and also if DoS incidents are detected. This is true if the events server is STIG compliant.

Note: If using the protocols TLS or LI-TLS to configure a secure connection to a log server, the server and client certificates must be stored in /var/vmware/nsx/file-store/ on each NSX-T Edge Gateway appliance.'
  impact 0.5
  tag check_id: 'C-55203r810191_chk'
  tag severity: 'medium'
  tag gid: 'V-251766'
  tag rid: 'SV-251766r863248_rule'
  tag stig_id: 'T1FW-3X-000026'
  tag gtitle: 'SRG-NET-000333-FW-000014'
  tag fix_id: 'F-55157r810192_fix'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']

  edgetns = http("https://#{input('nsxManager')}/policy/api/v1/search?query=( resource_type:TransportNode AND node_deployment_info.resource_type:EdgeNode )",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
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
                          'Cookie' => "#{input('sessionCookieId')}",
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
          logservers['results'].each do |logServer|
            describe json(content: logServer.to_json) do
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
