control 'HZNV-8X-000081' do
  title 'The Horizon Connection Server must offload events to a central log server in real time.'
  desc  "
     Information system logging capability is critical for accurate forensic analysis. Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records.

    The Horizon Connection Server can be configured to ship all events to a syslog receiver. Multiple servers can be configured but only the UDP protocol is supported at this time.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Event Configuration.

    The configured syslog servers are located in the right pane under \"Syslog\".

    If there are no valid syslog servers configured, this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Event Configuration.

    In the right pane, under \"Syslog\", click \"Add\".

    Enter the address of your central log server and configure the port if necessary.

    Click \"OK\".

    Repeat for other servers as applicable.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag satisfies: ['SRG-APP-000125-AS-000084', 'SRG-APP-000515-AS-000203']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000081'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-4 (1)', 'AU-9 (2)']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/Syslog/Get')

  loginfo = JSON.parse(result.stdout)

  allowed = input('syslogAddresses')
  syslogitems = loginfo['udpData']['networkAddresses']

  describe syslogitems do
    it { should_not cmp nil }
  end

  unless syslogitems.nil?
    syslogitems.each do |item|
      describe allowed do
        it { should include item }
      end
    end
  end
end
