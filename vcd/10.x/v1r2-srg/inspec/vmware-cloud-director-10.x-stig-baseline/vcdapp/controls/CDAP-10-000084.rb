control 'CDAP-10-000084' do
  title 'Cloud Director must compare internal application server clocks at least every 24 hours with an authoritative time source.'
  desc  "
    Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

    Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system compare its internal clock at least every 24 hours.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the NTP configuration by running the following commands on each appliance:

    # systemctl status systemd-timesyncd.service

    If the systemd-timesyncd service is not enabled and running, this is a finding.

    # grep ^NTP /etc/systemd/timesyncd.conf

    Example output:

    NTP=tick.usno.navy.mil

    If no NTP servers are configured or the configured NTP servers are not an authoritative time source, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/systemd/timesyncd.conf

    Add or update the NTP entry with the correct time server(s), for example:

    NTP=tick.usno.navy.mil

    Restart the systemd-timesyncd service by running the following command:

    # systemctl restart systemd-timesyncd.service

    To enable and start the systemd-timesyncd service, run the following commands:

    # systemctl enable systemd-timesyncd.service
    # systemctl start systemd-timesyncd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371-AS-000077'
  tag satisfies: ['SRG-APP-000372-AS-000212', 'SRG-APP-000920-AS-000320']
  tag gid: 'V-CDAP-10-000084'
  tag rid: 'SV-CDAP-10-000084'
  tag stig_id: 'CDAP-10-000084'
  tag cci: ['CCI-004922', 'CCI-004923', 'CCI-004926']
  tag nist: ['SC-45', 'SC-45 (1) (a)', 'SC-45 (1) (b)']

  describe file('/etc/systemd/timesyncd.conf') do
    its('content') { should match /^NTP=#{input('ntpServers')}/ }
  end
  describe systemd_service('systemd-timesyncd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
