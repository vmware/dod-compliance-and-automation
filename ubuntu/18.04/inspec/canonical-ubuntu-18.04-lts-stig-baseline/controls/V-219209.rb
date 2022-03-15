control 'V-219209' do
  title "The Ubuntu operating system must have directories that contain system
commands group-owned by root."
  desc  "If the Ubuntu operating system were to allow any user to make changes
to software libraries, then those changes might be implemented without
undergoing the appropriate testing and approvals that are part of a robust
change management process.

    This requirement applies to Ubuntu operating systems with software
libraries that are accessible and configurable, as in the case of interpreted
languages. Software libraries also include privileged programs which execute
with escalated privileges. Only qualified and authorized individuals must be
allowed to obtain access to information system components for purposes of
initiating changes, including upgrades and modifications.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the system commands directories are group-owned by root:

    /bin
    /sbin
    /usr/bin
    /usr/sbin
    /usr/local/bin
    /usr/local/sbin

    Run the check with the following command:

    # sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
! -group root -type d -exec stat -c \"%n %G\" '{}' \\;

    If any system commands directories are returned that are not Set Group ID
up on execution (SGID) files and owned by a privileged account, this is a
finding.
  "
  desc 'fix', "
    Configure the system commands directories to be protected from unauthorized
access. Run the following command:

    # sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
! -group root -type d -exec chgrp root '{}' \\;
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-219209'
  tag rid: 'SV-219209r508662_rule'
  tag stig_id: 'UBTU-18-010144'
  tag fix_id: 'F-20933r304956_fix'
  tag cci: %w(V-100645 SV-109749 CCI-001499)
  tag nist: ['CM-5 (6)']

  system_commands = command('find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d').stdout.strip.split("\n").entries
  valid_system_commands = Set[]

  if system_commands.count > 0
    system_commands.each do |sys_cmd|
      if file(sys_cmd).exist?
        valid_system_commands = valid_system_commands << sys_cmd
      end
    end
  end

  if valid_system_commands.count > 0
    valid_system_commands.each do |val_sys_cmd|
      describe file(val_sys_cmd) do
        its('group') { should cmp 'root' }
      end
    end
  else
    describe "Number of directories that contain system commands found in /bin, /sbin, /usr/bin, /usr/sbin,
      /usr/local/bin or /usr/local/sbin, that are NOT group-owned by root" do
      subject { valid_system_commands }
      its('count') { should eq 0 }
    end
  end
end
