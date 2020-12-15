# encoding: UTF-8

control 'V-219201' do
  title 'The Ubuntu operating system library directories must be owned by root.'
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
\"/usr/lib\" are owned by root.

    Check that the system-wide shared library directories are owned by root
with the following command:

    # sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c \"%n
%U\" '{}' \\;

    If any system wide library directory is returned, this is a finding.
  "
  desc  'fix', "
    Configure the library files and their respective parent directories to be
protected from unauthorized access. Run the following command:

    # sudo find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}'
\\;
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-219201'
  tag rid: 'SV-219201r508662_rule'
  tag stig_id: 'UBTU-18-010136'
  tag fix_id: 'F-20925r304932_fix'
  tag cci: ['SV-109733', 'V-100629', 'CCI-001499']
  tag nist: ['CM-5 (6)']

  if os.arch == "x86_64"
    library_dirs = command('find /lib /usr/lib /usr/lib32 /lib32 /lib64 ! \-user root \-type d').stdout.strip.split("\n").entries
  else
    library_dirs = command('find /lib /usr/lib /usr/lib32 /lib32 ! \-user root \-type d').stdout.strip.split("\n").entries
  end

  if library_dirs.count > 0
    library_dirs.each do |lib_file|
      describe file(lib_file) do
        its("owner") { should cmp "root" }
      end
    end
  else
    describe "Number of system-wide shared library directories found that are NOT owned by root" do
      subject { library_dirs }
      its("count") { should eq 0 }
    end
  end
end

