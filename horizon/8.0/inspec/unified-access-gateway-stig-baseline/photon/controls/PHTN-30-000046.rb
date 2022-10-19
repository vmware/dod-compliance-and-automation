control 'PHTN-30-000046' do
  title 'The Photon operating system must initiate auditing as part of the boot process.'
  desc  'Each process on the system carries an "auditable" flag, which indicates whether its activities can be audited. Although auditd takes care of enabling this for all processes that launch after it starts, adding the kernel argument ensures the flag is set at boot for every process on the system. This includes processes created before auditd starts.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # grep \"audit=1\" /proc/cmdline

    If no results are returned, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /boot/grub2/grub.cfg

    Locate the boot command line arguments. An example follows:

    linux /$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline

    Add \"audit=1\" to the end of the line so it reads as follows:

    linux /$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline audit=1

    Note: Do not copy/paste in this example argument line. This may change in future releases. Find the similar line and append \"audit=1\" to it.

    Reboot the system for the change to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000046'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  describe file('/boot/grub2/grub.cfg') do
    # Regex matches start of line followed anything then the word 'linux' followed by 'photon_linux' then anything and 'audit=1'
    its('content') { should match /^(?=.*?\blinux\b)(?=.*?\bphoton_linux\b)(?=.*?\baudit=1\b).*$/ }
  end
end
