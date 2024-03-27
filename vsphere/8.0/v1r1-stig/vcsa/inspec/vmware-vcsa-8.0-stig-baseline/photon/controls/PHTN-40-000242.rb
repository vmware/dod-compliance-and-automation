control 'PHTN-40-000242' do
  title 'The Photon operating system must enable the rsyslog service.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'If another package is used to offload logs, such as syslog-ng, and is properly configured, this is not applicable.

At the command line, run the following command to verify rsyslog is enabled and running:

# systemctl status rsyslog

If the rsyslog service is not enabled and running, this is a finding.'
  desc 'fix', 'At the command line, run the following commands:

# systemctl enable rsyslog
# systemctl start rsyslog'
  impact 0.5
  tag check_id: 'C-62641r933762_chk'
  tag severity: 'medium'
  tag gid: 'V-258901'
  tag rid: 'SV-258901r933764_rule'
  tag stig_id: 'PHTN-40-000242'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62550r933763_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end
