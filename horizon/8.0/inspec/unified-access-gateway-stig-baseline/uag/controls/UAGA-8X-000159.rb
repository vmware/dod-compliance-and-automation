control 'UAGA-8X-000159' do
  title 'The UAG must disable host time synchronization and utilize authoritative NTP time sources.'
  desc  "
    Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

    Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization must define authoritative time sources and configure each UAG system to utilize the authoritative time sources.

    The UAG does provide an option to synchronize the time with the ESXi host, only if running on a VMware ESXi host. This option must be disabled, and NTP time servers configured, in order to ensure all components (servers, hosts, network devices, etc) are utilizing the same NTP time sources.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    If the \"Time Sync With Host\" toggle is enabled, this is a finding.

    If the \"NTP Servers\" does not contain a list of valid authoritative NTP time sources, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    Ensure the \"Time Sync With Host\" toggle is disabled.

    Ensure the \"NTP Servers\" section contains a list of valid authoritative NTP time sources.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000159'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = uaghelper.runrestcommand('rest/v1/config/system')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent['hostClockSyncEnabled'] do
      it { should cmp false }
    end

    input('authoritativeNTPServers').each do |ntp|
      describe jsoncontent['ntpServers'] do
        it { should include ntp }
      end
    end
  end
end
