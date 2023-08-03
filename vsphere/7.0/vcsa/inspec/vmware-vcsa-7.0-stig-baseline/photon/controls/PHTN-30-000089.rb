control 'PHTN-30-000089' do
  title 'The Photon operating system must be configured so the x86 Ctrl-Alt-Delete key sequence is disabled on the command line.'
  desc 'When the Ctrl-Alt-Del target is enabled, a locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed operating system environment, this can create the risk of short-term loss of systems availability due to unintentional reboot.'
  desc 'check', 'At the command line, run the following command:

# systemctl status ctrl-alt-del.target

Expected result:

ctrl-alt-del.target
Loaded: masked (/dev/null; bad)
Active: inactive (dead)

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, run the following command:

# systemctl mask ctrl-alt-del.target'
  impact 0.5
  tag check_id: 'C-60233r887346_chk'
  tag severity: 'medium'
  tag gid: 'V-256558'
  tag rid: 'SV-256558r887348_rule'
  tag stig_id: 'PHTN-30-000089'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60176r887347_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe systemd_service('ctrl-alt-del.target') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
