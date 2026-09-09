control 'PHTN-50-000080' do
  title 'The Photon operating system must initiate session audits at system start-up.'
  desc  'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify auditing is enabled at start-up:

    # grep 'audit' /proc/cmdline

    Example result:

    BOOT_IMAGE=/boot/vmlinuz-5.10.109-2.ph4-esx root=PARTUUID=6e6293c6-9ab6-49e9-aa97-9b212f2e037a init=/lib/systemd/systemd rcupdate.rcu_expedited=1 rw systemd.show_status=1 quiet noreplace-smp cpu_init_udelay=0 plymouth.enable=0 systemd.legacy_systemd_cgroup_controller=yes audit=1

    If the \"audit\" parameter is not present with a value of \"1\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /boot/grub2/grub.cfg

    Locate the boot command line arguments. An example follows:

    linux /boot/$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline

    Add \"audit=1\" to the end of the line so it reads as follows:

    linux /boot/$photon_linux root=$rootpartition $photon_cmdline $systemd_cmdline audit=1

    Note: Do not copy/paste in this example argument line. This may change in future releases. Find the similar line and append \"audit=1\" to it.

    Reboot the system for the change to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag gid: 'V-PHTN-50-000080'
  tag rid: 'SV-PHTN-50-000080'
  tag stig_id: 'PHTN-50-000080'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']

  describe command('cat /proc/cmdline') do
    its('stdout.strip') { should match /audit=1/ }
  end
end
