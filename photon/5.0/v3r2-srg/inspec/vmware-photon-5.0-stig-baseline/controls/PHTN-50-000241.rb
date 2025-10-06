control 'PHTN-50-000241' do
  title 'The Photon operating system must install rsyslog for offloading of audit logs.'
  desc  'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading is a common process in information systems with limited audit storage capacity.'
  desc  'rationale', ''
  desc  'check', "
    This is not applicable to the following VCF components: Operations HCX.

    At the command line, run the following commands to verify rsyslog is installed:

    # rpm -qa | grep '^rsyslog-'

    Example result:

    rsyslog-8.2212.0-1.ph5.x86_64

    If rsyslog is not installed, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following command:

    # tdnf install rsyslog
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000241'
  tag rid: 'SV-PHTN-50-000241'
  tag stig_id: 'PHTN-50-000241'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('rsyslog') do
    it { should be_installed }
  end
end
