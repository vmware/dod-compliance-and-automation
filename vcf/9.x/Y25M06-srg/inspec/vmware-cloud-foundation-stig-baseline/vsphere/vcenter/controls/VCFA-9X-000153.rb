control 'VCFA-9X-000153' do
  title 'The VMware Cloud Foundation vCenter Server must compare internal information system clocks with an authoritative time server.'
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.

    Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).
  "
  desc  'rationale', ''
  desc  'check', "
    Open the vCenter Server Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

    Log in with local operating system administrative credentials or with a single sign-on (SSO) account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Time\" on the left navigation pane.

    Verify at least one authorized time server is configured.

    If the NTP servers listed are not site specific authoritative time sources, this is a finding.
  "
  desc 'fix', "
    Open the VAMI by navigating to https://<vCenter server>:5480.

    Log in with local operating system administrative credentials or with an SSO account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Time\" on the left navigation pane.

    On the resulting pane on the right, click \"Edit\" next to \"Time Synchronization\".

    Select \"NTP\" for \"Mode\" and enter a list of authorized time servers separated by commas. Click \"Save\".

    Note: It is recommended to configure 1 or 3 or more NTP servers to help prevent \"split-brain\" scenarios.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371'
  tag satisfies: ['SRG-APP-000372', 'SRG-APP-000920', 'SRG-APP-000925']
  tag gid: 'V-VCFA-9X-000153'
  tag rid: 'SV-VCFA-9X-000153'
  tag stig_id: 'VCFA-9X-000153'
  tag cci: ['CCI-004922', 'CCI-004923', 'CCI-004926']
  tag nist: ['SC-45', 'SC-45 (1) (a)', 'SC-45 (1) (b)']

  command = 'Invoke-GetTimesync -Confirm:$false'
  result = powercli_command(command).stdout.strip

  if result.blank?
    describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
      skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
    end
  elsif result == 'NTP'
    ntpserverscommand = 'Invoke-GetNtp -Confirm:$false'
    ntpservers = powercli_command(ntpserverscommand).stdout.gsub("\r\n", "\n").split("\n")
    ntpservers.each do |server|
      describe "The NTP server: #{server}" do
        subject { server }
        it { should be_in input('vcenter_ntpServers') }
      end
      ntpstatuscommand = "Initialize-ApplianceNtpTestrequest -Servers #{server} | Invoke-TestNtp -Confirm:$false | ConvertTo-Json -Depth 1 -WarningAction SilentlyContinue"
      ntpstatus = powercli_command(ntpstatuscommand).stdout.strip
      describe "The NTP server: #{server}" do
        subject { json(content: ntpstatus) }
        its(['Status']) { should cmp 'SERVER_REACHABLE' }
      end
    end
  else
    describe 'vCenter time synchronization mode' do
      subject { result }
      it { should cmp 'NTP' }
    end
  end
end
