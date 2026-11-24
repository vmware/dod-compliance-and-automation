control 'UBTU-24-102010' do
  title 'Ubuntu 24.04 LTS must initiate session audits at system startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Verify Ubuntu 24.04 LTS enables auditing at system startup in GRUB.

Check the main GRUB defaults to ensure that auditing is enabled:
$ sudo grep -ir GRUB_CMDLINE_LINUX /etc/default/grub
/etc/default/grub:GRUB_CMDLINE_LINUX_DEFAULT="audit=1"
/etc/default/grub:GRUB_CMDLINE_LINUX="audit=1"

If any linux lines do not contain "audit=1", this is a finding.

Check the generated GRUB configuration to ensure that the setting is propagated to the bootloader:
$ sudo grep "^\\s*linux" /boot/grub/grub.cfg
linux   /vmlinuz-6.8.0-31-generic root=UUID=c92a542f-aee4-4af9-94b2-203624ccb8e3 ro audit=1 quiet splash $vt_handoff
linux   /vmlinuz-6.8.0-31-generic root=UUID=c92a542f-aee4-4af9-94b2-203624ccb8e3 ro recovery nomodeset dis_ucode_ldr audit=1

If any linux lines do not contain "audit=1", this is a finding.

Note: Output details may vary by system.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to produce audit records at system startup.

Edit the "/etc/default/grub" file and add "audit=1" to the "GRUB_CMDLINE_LINUX" option and to the "GRUB_CMDLINE_LINUX_DEFAULT" option.

GRUB_CMDLINE_LINUX_DEFAULT="audit=1"
GRUB_CMDLINE_LINUX="audit=1"

To update the grub config file, run:

$ sudo update-grub'
  impact 0.5
  tag check_id: 'C-74709r1155230_chk'
  tag severity: 'medium'
  tag gid: 'V-270676'
  tag rid: 'SV-270676r1155245_rule'
  tag stig_id: 'UBTU-24-102010'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-74610r1155231_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  grub_default_file = '/etc/default/grub'

  describe file(grub_default_file) do
    it { should exist }
  end

  grub_cmdline_linux_default = command("grep -i '^GRUB_CMDLINE_LINUX_DEFAULT=' #{grub_default_file} 2>/dev/null || true").stdout.strip
  grub_cmdline_linux = command("grep -i '^GRUB_CMDLINE_LINUX=' #{grub_default_file} 2>/dev/null || true").stdout.strip

  describe 'GRUB_CMDLINE_LINUX_DEFAULT' do
    subject { grub_cmdline_linux_default }
    it 'should contain audit=1' do
      should match(/audit=1/)
    end
  end

  describe 'GRUB_CMDLINE_LINUX' do
    subject { grub_cmdline_linux }
    it 'should contain audit=1' do
      should match(/audit=1/)
    end
  end

  grub_cfg_file = '/boot/grub/grub.cfg'

  describe file(grub_cfg_file) do
    it { should exist }
  end

  grub_cfg_linux = command("grep '^\\s*linux' #{grub_cfg_file} 2>/dev/null || true").stdout.split("\n")

  describe 'GRUB_CFG_LINUX' do
    subject { grub_cfg_linux }
    it { should_not be_empty }
    it 'should contain audit=1 on every linux line' do
      subject.each do |line|
        expect(line).to match(/audit=1/)
      end
    end
  end
end
