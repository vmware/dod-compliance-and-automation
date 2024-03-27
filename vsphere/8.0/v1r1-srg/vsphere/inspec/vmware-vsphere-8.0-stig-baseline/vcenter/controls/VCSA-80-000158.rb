control 'VCSA-80-000158' do
  title 'The vCenter Server must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.

    Synchronizing internal information system clocks to an authoritative time server provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
  "
  desc  'rationale', ''
  desc  'check', "
    Open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

    Log in with local operating system administrative credentials or with a Single Sign-On (SSO) account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Time\" on the left navigation pane.

    On the resulting pane on the right, verify at least one authorized time server is configured and is listed as \"Reachable\".

    If \"NTP\" is not enabled and at least one authorized time server configured, this is a finding.
  "
  desc 'fix', "
    Open the VAMI by navigating to https://<vCenter server>:5480.

    Log in with local operating system administrative credentials or with an SSO account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Time\" on the left navigation pane.

    On the resulting pane on the right, click \"Edit\" under \"Time Synchronization\".

    Select \"NTP\" for \"Mode\" and enter a list of authorized time servers separated by commas. Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371'
  tag gid: 'V-VCSA-80-000158'
  tag rid: 'SV-VCSA-80-000158'
  tag stig_id: 'VCSA-80-000158'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']

  command = 'Invoke-GetTimesync'
  timesync = powercli_command(command).stdout.strip

  if timesync == 'NTP'
    ntpserverscommand = 'Invoke-GetNtp'
    ntpservers = powercli_command(ntpserverscommand).stdout.gsub("\r\n", "\n").split("\n")
    ntpservers.each do |server|
      describe server do
        subject { server }
        it { should be_in input('ntpServers') }
      end
      ntpstatuscommand = "Initialize-NtpTestRequestBody -Servers #{server} | Invoke-TestNtp | Select-Object -ExpandProperty status"
      ntpstatus = powercli_command(ntpstatuscommand).stdout.strip
      describe ntpstatus do
        subject { ntpstatus }
        it { should cmp 'SERVER_REACHABLE' }
      end
    end
  else
    describe "Timesync Configuration: #{timesync}" do
      subject { timesync }
      it { should cmp 'NTP' }
    end
  end
end
