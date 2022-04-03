control 'PHTN-67-000114' do
  title 'The Photon OS must not have the xinetd service enabled.'
  desc  "The xinetd service is not required for normal appliance operation and
must be disabled."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # systemctl is-enabled xinetd.service

    Expected result:

    disabled

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following commands:

    # service xinetd stop
    # systemctl disable xinetd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239185'
  tag rid: 'SV-239185r675363_rule'
  tag stig_id: 'PHTN-67-000114'
  tag fix_id: 'F-42355r675362_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('xinetd.service') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
