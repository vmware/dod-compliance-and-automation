control 'VCFN-9X-000085' do
  title 'The VMware Cloud Foundation NSX Manager must be configured to send logs to a central log server.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and verify the Syslog servers listed.

    or

    From an NSX Manager shell, run the following command:

    > get logging-servers

    Note: This command must be run from each NSX Manager as they are configured individually.

    If no logging severs are configured or unauthorized logging servers are configured, this is a finding.

    If the log level is not set to INFO, this is a finding.
  "
  desc 'fix', "
    To configure a profile to apply syslog servers to all NSX Manager nodes, do the following:

    From the NSX Manager web interface, go to System >> Fabric >> Profiles >> Node Profiles.

    Click \"All NSX Nodes\" and then under \"Syslog Servers\" click \"Add\".

    Enter the syslog server details and choose \"Information\" for the log level and click \"Add\".

    or

    (Optional) From an NSX Manager shell, run the following command to clear any existing incorrect logging-servers:

    > clear logging-servers

    From an NSX Manager shell, run the following command to configure a udp/tcp syslog server:

    > set logging-server <server-ip or server-name> proto <tcp or udp> level info

    From an NSX Manager shell, run the following command to configure a TLS syslog server:

    > set logging-server <server-ip or server-name> proto tls level info serverca ca.pem clientca ca.pem certificate cert.pem key key.pem

    From an NSX Manager shell, run the following command to configure an LI-TLS syslog server:

    > set logging-server <server-ip or server-name> proto li-tls level info serverca root-ca.crt

    Note: If using the protocols TLS or LI-TLS to configure a secure connection to a log server, the server and client certificates must be stored in /image/vmware/nsx/file-store on each NSX-T Manager appliance.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag satisfies: ['SRG-APP-000357-NDM-000293', 'SRG-APP-000516-NDM-000350']
  tag gid: 'V-VCFN-9X-000085'
  tag rid: 'SV-VCFN-9X-000085'
  tag stig_id: 'VCFN-9X-000085'
  tag cci: ['CCI-001849', 'CCI-001851']
  tag nist: ['AU-4', 'AU-4 (1)']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/node/services/syslog/status",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('runtime_state') { should cmp 'running' }
    end
  end

  result = http("https://#{input('nsx_managerAddress')}/api/v1/node/services/syslog/exporters",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    logservers = JSON.parse(result.body)
    if logservers['results'].empty?
      describe 'The number of syslog servers' do
        subject { logservers['results'] }
        it { should_not be_empty }
      end
    else
      logservers['results'].each do |logserver|
        describe json(content: logserver.to_json) do
          its('level') { should cmp 'INFO' }
          its('server') { should be_in "#{input('nsx_syslogServers')}" }
        end
      end
    end
  end
end
