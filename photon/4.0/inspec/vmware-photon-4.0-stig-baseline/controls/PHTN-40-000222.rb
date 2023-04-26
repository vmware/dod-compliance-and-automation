control 'PHTN-40-000222' do
  title 'The Photon operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.'
  desc  'When the Ctrl-Alt-Del target is enabled, a locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of systems availability due to unintentional reboot.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the ctrl-alt-del target is disabled:

    # systemctl status ctrl-alt-del.target

    If the ctrl-alt-del.target is not inactive and disabled, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following command:

    # systemctl mask ctrl-alt-del.target
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-40-000222'
  tag rid: 'SV-PHTN-40-000222'
  tag stig_id: 'PHTN-40-000222'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # ctrl-alt-del.target is really an alias for reboot.target so test uses reboot.target in order to work correctly
  describe systemd_service('reboot.target') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
