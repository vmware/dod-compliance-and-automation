control 'PHTN-50-000222' do
  title 'The Photon operating system must be configured so that the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.'
  desc  'When the Ctrl-Alt-Del target is enabled, a locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of systems availability due to unintentional reboot.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the ctrl-alt-del target is disabled and masked:

    # systemctl status ctrl-alt-del.target --no-pager

    Example output:

    ctrl-alt-del.target
    \tLoaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
    \tActive: inactive (dead)

    If the \"ctrl-alt-del.target\" is not \"inactive\" and \"masked\", this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands:

    # systemctl disable ctrl-alt-del.target
    # systemctl mask ctrl-alt-del.target
    # systemctl daemon-reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000222'
  tag rid: 'SV-PHTN-50-000222'
  tag stig_id: 'PHTN-50-000222'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('ctrl-alt-del.target') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
  describe systemd_service('ctrl-alt-del.target').params['LoadState'] do
    it { should cmp 'masked' }
  end
  describe systemd_service('ctrl-alt-del.target').params['UnitFileState'] do
    it { should cmp 'masked' }
  end
end
