control 'VRAA-8X-000009' do
  title 'VMware Aria Automation must synchronize time from an authoritative time source.'
  desc  "
    Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

    Synchronization of system clocks is necessary in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system compare its internal clock at least every 24 hours.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # vracli ntp show-config

    If the output does not show \"ntp_enabled: True\", this is a finding.

    If the output does not show \"ntp_servers:\" with one or more authoritative NTP servers configured , this is a finding.
  "
  desc 'fix', "
    At the command line, run the following command:

    # vracli ntp systemd --set <time_server_IP_or_FQDN>

    Note: You can add multiple NTP servers by separating their network addresses with a comma.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371-AS-000077'
  tag satisfies: ['SRG-APP-000116-AS-000076', 'SRG-APP-000372-AS-000212']
  tag gid: 'V-VRAA-8X-000009'
  tag rid: 'SV-VRAA-8X-000009'
  tag stig_id: 'VRAA-8X-000009'
  tag cci: ['CCI-000159', 'CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)', 'AU-8 a']

  # Get ntp enabled settings (cluster will return multiple lines)
  ntp_enabled_settings = command('vracli ntp show-config | grep ntp_enabled').stdout.strip.split("\n")

  if ntp_enabled_settings.blank?
    describe 'NTP must be enabled' do
      subject { ntp_enabled_settings }
      it { should_not be_blank }
    end
  else
    # Loop through results, all should be enabled
    ntp_enabled_settings.each do |ntp_enabled|
      describe 'NTP enabled' do
        subject { ntp_enabled.strip }
        it { should cmp 'ntp_enabled: True' }
      end
    end
  end

  # Get ntp server settings (cluster will return multiple lines)
  ntp_servers = command('vracli ntp show-config | grep ntp_servers').stdout.strip.split("\n")

  if ntp_servers.blank?
    describe 'NTP must be configured' do
      subject { ntp_servers }
      it { should_not be_blank }
    end
  else
    # Loop through results, all should be set the same (if clustered)
    ntp_servers.each do |ntp_server|
      describe 'NTP server list' do
        subject { ntp_server.strip }
        it { should cmp "ntp_servers: #{input('automationNtpServers')}" }
      end
    end
  end
end
