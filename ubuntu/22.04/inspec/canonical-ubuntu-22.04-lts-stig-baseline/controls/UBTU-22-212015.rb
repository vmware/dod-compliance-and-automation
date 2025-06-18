control 'UBTU-22-212015' do
  title 'Ubuntu 22.04 LTS must initiate session audits at system startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Verify that Ubuntu 22.04 LTS enables auditing at system startup in grub by using the following command:

$ sudo grep "^\\s*linux" /boot/grub/grub.cfg

linux        /boot/vmlinuz-5.4.0-31-generic root=UUID=74d13bcd-6ebd-4493-b5d2-3ebc37d01702 ro  audit=1
linux      /boot/vmlinuz-5.4.0-31-generic root=UUID=74d13bcd-6ebd-4493-b5d2-3ebc37d01702 ro recovery nomodeset audit=1

If any linux lines do not contain "audit=1", this is a finding.

Note: Output may vary by system.'
  desc 'fix', 'Configure the Ubuntu operating system to produce audit records at system startup.

Edit the "/etc/default/grub" file and add "audit=1" to the "GRUB_CMDLINE_LINUX" option and to the "GRUB_CMDLINE_LINUX_DEFAULT" option.

GRUB_CMDLINE_LINUX_DEFAULT="audit=1"
GRUB_CMDLINE_LINUX="audit=1"

To update the grub config file, run:

$ sudo update-grub'
  impact 0.5
  tag check_id: 'C-64200r1069115_chk'
  tag severity: 'medium'
  tag gid: 'V-260471'
  tag rid: 'SV-260471r1069117_rule'
  tag stig_id: 'UBTU-22-212015'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-64108r1069116_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  grub_entries = command('grep "^\s*linux" /boot/grub/grub.cfg').stdout.strip.split("\n").entries

  grub_entries.each do |entry|
    describe entry do
      it { should include 'audit=1' }
    end
  end
end
