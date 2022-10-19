control 'PHTN-30-000089' do
  title 'The Photon operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.'
  desc  'When the Ctrl-Alt-Del target is enabled, a locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of systems availability due to unintentional reboot.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # systemctl status ctrl-alt-del.target

    Expected result:

    ctrl-alt-del.target
    Loaded: masked (/dev/null; bad)
    Active: inactive (dead)

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command:

    # systemctl mask ctrl-alt-del.target
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000089'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('ctrl-alt-del.target') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
