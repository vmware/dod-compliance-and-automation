control 'NT0F-4X-000020' do
  title 'The NSX Tier-0 Gateway Firewall must be configured to send traffic log entries to a central audit server.'
  desc  "
    Without the ability to centrally manage the content captured in the traffic log entries, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

    The DOD requires centralized management of all network component audit record content. Network components requiring centralized traffic log management must have the ability to support centralized management. The content captured in traffic log entries must be managed from a central location (necessitating automation). Centralized management of traffic log records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

    Ensure at least one syslog server is configured on the firewall.

    If the product inherently has the ability to store log records locally, the local log must also be secured. However, this requirement is not met since it calls for a use of a central audit server.
  "
  desc  'rationale', ''
  desc  'check', "
    From an NSX Edge Node shell hosting the Tier-0 Gateway, run the following command:

    > get logging-servers

    Note: This check must be run from each NSX Edge Node hosting a Tier-0 Gateway, as they are configured individually.

    or

    If Node Profiles are used, from the NSX Manager web interface, go to System >> Configuration >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and verify the Syslog servers listed.

    If any configured logging servers are configured with a protocol of \"udp\", this is a finding.

    If any configured logging servers are not configured with a level of \"info\", this is a finding.

    If no logging-servers are configured, this is a finding.
  "
  desc 'fix', "
    To configure a profile to apply syslog servers to all NSX Edge Nodes, do the following:

    From the NSX Manager web interface, go to System >> Configuration >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and then under \"Syslog Servers\" click \"Add\".

    Enter the syslog server details and choose \"Information\" for the log level and click \"Add\".

    or

    (Optional) From an NSX Edge Node shell, run the following command to clear any existing incorrect logging-servers:

    > clear logging-servers

    From an NSX Edge Node shell, run the following command to configure a tcp syslog server:

    > set logging-server <server-ip or server-name> proto tcp level info

    From an NSX Edge Node shell, run the following command to configure a primary and backup tls syslog server:

    > set logging-server <server-ip or server-name> proto tls level info serverca ca.pem clientca ca.pem certificate cert.pem key key.pem

    From an NSX Edge Node shell, run the following command to configure a li-tls syslog server:

    > set logging-server <server-ip or server-name> proto li-tls level info serverca root-ca.crt

    Note: If using the protocols TLS or LI-TLS to configure a secure connection to a log server, the server and client certificates must be stored in /var/vmware/nsx/file-store/ on each NSX Edge Node appliance.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000333-FW-000014'
  tag satisfies: ['SRG-NET-000098-FW-000021']
  tag gid: 'V-NT0F-4X-000020'
  tag rid: 'SV-NT0F-4X-000020'
  tag stig_id: 'NT0F-4X-000020'
  tag cci: ['CCI-000366', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'CM-6 b']

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
      impact 0.0
      describe 'No Edge Node Transports are deployed. This is Not Applicable.' do
        skip 'No Edge Node Transports are deployed. This is Not Applicable.'
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
              its('protocol') { should be_in ['TCP', 'TLS', 'LI-TLS'] }
              its('server') { should be_in "#{input('syslogServers')}" }
            end
          end
        end
      end
    end
  end
end
