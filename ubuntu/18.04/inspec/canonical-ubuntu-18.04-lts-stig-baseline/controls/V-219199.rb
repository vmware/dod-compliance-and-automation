# encoding: UTF-8

control 'V-219199' do
  title "The Ubuntu operating system library directories must have mode 0755 or
less permissive."
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
    Verify the system-wide shared library directories \"/lib\", \"/lib64\" and
\"/usr/lib have mode 0755 or less permissive.

    Check that the system-wide shared library directories have mode 0755 or
less permissive with the following command:

    # sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec stat -c \"%n %a\"
'{}' \\;

    If any of the aforementioned directories are found to be group-writable or
world-writable, this is a finding.
  "
  desc  'fix', "
    Configure the shared library directories to be protected from unauthorized
access. Run the following command:

    # sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}' \\;
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-219199'
  tag rid: 'SV-219199r508662_rule'
  tag stig_id: 'UBTU-18-010134'
  tag fix_id: 'F-20923r485739_fix'
  tag cci: ['V-100625', 'SV-109729', 'CCI-001499']
  tag nist: ['CM-5 (6)']

  if os.arch == 'x86_64'
    library_dirs = command('find /lib /lib32 lib64 /usr/lib /usr/lib32 -perm /022 -type d').stdout.strip.split("\n").entries
  else
    library_dirs = command('find /lib /usr/lib /usr/lib32 /lib32 -perm /022 -type d').stdout.strip.split("\n").entries
  end

  if library_dirs.count > 0
    library_dirs.each do |lib_file|
      describe file(lib_file) do
        it { should_not be_more_permissive_than('0755') }
      end
    end
  else
    describe 'Number of system-wide shared library directories found that are less permissive than 0755' do
      subject { library_dirs }
      its('count') { should eq 0 }
    end
  end
end

