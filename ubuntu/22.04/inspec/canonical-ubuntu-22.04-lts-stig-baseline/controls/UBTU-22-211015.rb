control 'UBTU-22-211015' do
  title 'Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed by using the following command:

     $ systemctl status ctrl-alt-del.target
     ctrl-alt-del.target
          Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
          Active: inactive (dead)

If the "ctrl-alt-del.target" is not masked, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to disable the Ctrl-Alt-Delete sequence for the command line by using the following commands:

     $ sudo systemctl disable ctrl-alt-del.target

     $ sudo systemctl mask ctrl-alt-del.target

Reload the daemon to take effect:

     $ sudo systemctl daemon-reload'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64198r953218_chk'
  tag severity: 'high'
  tag gid: 'V-260469'
  tag rid: 'SV-260469r991589_rule'
  tag stig_id: 'UBTU-22-211015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-64106r953219_fix'
  tag 'documentable'
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
