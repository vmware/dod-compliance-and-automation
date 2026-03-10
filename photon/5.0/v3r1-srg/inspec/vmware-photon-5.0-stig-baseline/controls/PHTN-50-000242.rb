control 'PHTN-50-000242' do
  title 'The Photon operating system must enable the rsyslog service.'
  desc  'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading is a common process in information systems with limited audit storage capacity.'
  desc  'rationale', ''
  desc  'check', "
    This is not applicable to the following VCF components: Operations HCX.

    At the command line, run the following command to verify rsyslog is enabled and running:

    # systemctl status rsyslog --no-pager

    If the rsyslog service is not enabled and running, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    # systemctl enable rsyslog
    # systemctl start rsyslog
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000242'
  tag rid: 'SV-PHTN-50-000242'
  tag stig_id: 'PHTN-50-000242'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end
