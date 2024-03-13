control 'WOAA-3X-000061' do
  title 'Workspace ONE Access must be configured to use NTP to synchronize time.'
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.

    If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose. Synchronizing the internal clock using NTP provides uniformity for all system clocks over a network. NTP provides an efficient and scalable method for network devices to synchronize to an accurate time source.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>:8443/cfg\" using administrative credentials.

    Click \"Time Synchronization\" in the left pane to view the current NTP configuration.

    If \"Time Sync\" is not set to \"NTP, this is a finding.

    If \"NTP Server\" is not set to an authoritative DoD time source, this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>:8443/cfg\" using administrative credentials.

    Click \"Time Synchronization\" in the left pane.

    Select NTP for the Time Sync method then enter the NTP server FQDN in the NTP Server field then click Save.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516-AAA-000350'
  tag gid: 'V-WOAA-3X-000061'
  tag rid: 'SV-WOAA-3X-000061'
  tag stig_id: 'WOAA-3X-000061'
  tag cci: ['CCI-000366', 'CCI-001891']
  tag nist: ['AU-8 (1) (a)', 'CM-6 b']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
