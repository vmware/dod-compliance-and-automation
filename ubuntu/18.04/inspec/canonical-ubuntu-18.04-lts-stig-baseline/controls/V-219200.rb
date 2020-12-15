# encoding: UTF-8

control 'V-219200' do
  title 'The Ubuntu operating system library files must be owned by root.'
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
    Verify the system-wide shared library files contained in the directories
\"/lib\", \"/lib64\" and \"/usr/lib\" are owned by root.

    Check that the system-wide shared library files are owned by root with the
following command:

    # sudo find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n
%U\" '{}' \\;

    If any system wide library file is returned, this is a finding.
  "
  desc  'fix', "
    Configure the system library files to be protected from unauthorized
access. Run the following command:

    # sudo find /lib /usr/lib /lib64 ! -user root -type f -exec chown root '{}'
\\;
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-219200'
  tag rid: 'SV-219200r508662_rule'
  tag stig_id: 'UBTU-18-010135'
  tag fix_id: 'F-20924r304929_fix'
  tag cci: ['SV-109731', 'V-100627', 'CCI-001499']
  tag nist: ['CM-5 (6)']

  if os.arch == "x86_64"
    library_files = command('find /lib /usr/lib /usr/lib32 /lib32 /lib64 ! \-user root \-type f').stdout.strip.split("\n").entries
  else
    library_files = command('find /lib /usr/lib /usr/lib32 /lib32 ! \-user root \-type f').stdout.strip.split("\n").entries
  end

  if library_files.count > 0
    library_files.each do |lib_file|
      describe file(lib_file) do
        its("owner") { should cmp "root" }
      end
    end
  else
    describe "Number of system-wide shared library files found that are NOT owned by root" do
      subject { library_files }
      its("count") { should eq 0 }
    end
  end
end

